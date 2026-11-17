// 诊断版: 追踪发送失败原因
// chat_gui_v3 + 日志输出到文件
#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define _WINSOCKAPI_
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/base/key.hpp"
#include "linoh/tls/handshake_token_key.hpp"

#include <string>
#include <vector>
#include <atomic>
#include <fstream>

using namespace linoh;
using namespace linoh::tls;
using namespace linoh::base;

static constexpr uint16_t SERVER_PORT = 54321;
static constexpr UINT WM_LOG = WM_USER + 1;

static const uint8_t DEMO_PSK[32] = {
    0x6c,0x69,0x6e,0x6f,0x68,0x2d,0x64,0x65,0x6d,0x6f,0x2d,0x70,0x73,0x6b,0x2d,0x30,
    0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30
};
static const char *AD_STR = "linoh-echo-demo";
static constexpr size_t AD_LEN = 13;

static HANDLE g_logHandle = INVALID_HANDLE_VALUE;

// 日志：直接用 CreateFile 写，不依赖 iostream 宽字符
static void open_log() {
    wchar_t path[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return;  // 静默失败，不阻止程序运行
    std::wstring p(path);
    size_t pos = p.find_last_of(L'\\');
    if (pos != std::wstring::npos) p = p.substr(0, pos + 1);
    p += L"chat_gui_v4_log.txt";

    g_logHandle = CreateFileW(p.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_logHandle == INVALID_HANDLE_VALUE) return;  // 静默失败
}

static void dlog(const wchar_t *fmt, ...) {
    if (g_logHandle == INVALID_HANDLE_VALUE) return;
    wchar_t buf[1024];
    va_list args;
    va_start(args, fmt);
    vswprintf_s(buf, fmt, args);
    va_end(args);
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t line[1200];
    swprintf_s(line, L"%02d:%02d:%02d.%03d %s\r\n",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, buf);
    DWORD written = 0;
    WriteFile(g_logHandle, line, (DWORD)(wcslen(line) * sizeof(wchar_t)), &written, NULL);
}

static std::wstring utf16_from_utf8(const std::string &s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, NULL, 0);
    if (n <= 1) return {};
    std::wstring r(n - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &r[0], n);
    return r;
}
static std::string utf8_from_utf16(const std::wstring &w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, NULL, 0, NULL, NULL);
    if (n <= 1) return {};
    std::string r(n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &r[0], n, NULL, NULL);
    return r;
}

struct AppState {
    HWND hwnd = nullptr;
    HWND hLog = nullptr;
    HWND hInput = nullptr;
    HWND hStatus = nullptr;
    SOCKET sock = INVALID_SOCKET;
    HandshakeTokenKey *tk = nullptr;
    EndpointId localId;
    std::atomic<uint32_t> nextSeq{1};
    std::atomic<bool> running{false};
    HANDLE hRecvThread = NULL;

    void queue_log(const wchar_t *text) {
        if (!hwnd) return;
        wchar_t *copy = _wcsdup(text);
        if (copy) {
            if (!PostMessageW(hwnd, WM_LOG, (WPARAM)copy, 0)) {
                dlog(L"[queue_log] PostMessageW 失败! err=%d", GetLastError());
                free(copy);
            }
        }
    }

    void cleanup() {
        running = false;
        if (hRecvThread) {
            WaitForSingleObject(hRecvThread, 3000);
            CloseHandle(hRecvThread);
            hRecvThread = NULL;
        }
        if (sock != INVALID_SOCKET) {
            closesocket(sock);
            sock = INVALID_SOCKET;
        }
        delete tk; tk = nullptr;
    }
};
static AppState *g_app = nullptr;

static DWORD WINAPI recv_thread(LPVOID param) {
    AppState *app = (AppState *)param;
    uint8_t buf[8192];

    while (app->running) {
        if (app->sock == INVALID_SOCKET) {
            Sleep(100);
            continue;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(app->sock, &rfds);
        timeval tv{0, 200000};
        int ret = select(0, &rfds, NULL, NULL, &tv);
        if (ret <= 0) continue;
        if (!app->running) break;

        int n = recvfrom(app->sock, (char *)buf, sizeof(buf), 0, NULL, NULL);
        if (n == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT) continue;
            dlog(L"[recv] recvfrom err=%d", err);
            break;
        }
        if (n < 4) continue;

        uint32_t rseq = (DWORD(buf[0]) << 24) | (DWORD(buf[1]) << 16) |
                         (DWORD(buf[2]) << 8) | DWORD(buf[3]);

        dlog(L"[recv] 收到 %d 字节, seq=%u", n, rseq);

        auto dec = app->tk->open(rseq,
            std::span<const uint8_t>((const uint8_t *)AD_STR, AD_LEN),
            std::span<const uint8_t>(buf + 4, n - 4));
        if (dec.empty()) {
            dlog(L"[recv] AEAD open 失败, seq=%u", rseq);
            wchar_t m[128];
            swprintf_s(m, L"!! AEAD 解密失败 (seq=%u)", rseq);
            app->queue_log(m);
            continue;
        }
        std::string reply((char *)dec.data(), dec.size());
        wchar_t m[600];
        swprintf_s(m, L"<< #%u %s", rseq, utf16_from_utf8(reply).c_str());
        app->queue_log(m);
    }
    dlog(L"[recv] 线程退出");
    return 0;
}

static void send_message(AppState *app, const wchar_t *text) {
    dlog(L"[send] 开始发送: '%s'", text);

    if (!text) { dlog(L"[send] text=null"); return; }
    if (!app) { dlog(L"[send] app=null"); return; }
    if (!app->tk) { dlog(L"[send] tk=null"); app->queue_log(L"!! AEAD key 未初始化"); return; }
    if (app->sock == INVALID_SOCKET) { dlog(L"[send] sock=INVALID"); app->queue_log(L"!! socket 未初始化"); return; }

    std::string msg = utf8_from_utf16(std::wstring(text));
    dlog(L"[send] utf8 len=%d", (int)msg.size());
    if (msg.empty()) { dlog(L"[send] utf8 转换失败"); return; }

    uint32_t seq = app->nextSeq.fetch_add(1);
    dlog(L"[send] seq=%u", seq);

    auto enc = app->tk->seal(seq,
        std::span<const uint8_t>((const uint8_t *)AD_STR, AD_LEN),
        std::span<const uint8_t>((const uint8_t *)msg.data(), msg.size()));
    dlog(L"[send] AEAD enc.size=%d", (int)enc.size());

    if (enc.empty()) {
        dlog(L"[send] AEAD seal 失败!");
        app->queue_log(L"!! AEAD 加密失败");
        return;
    }

    std::vector<uint8_t> pkt(4 + enc.size());
    pkt[0] = (uint8_t)((seq >> 24) & 0xFF);
    pkt[1] = (uint8_t)((seq >> 16) & 0xFF);
    pkt[2] = (uint8_t)((seq >> 8) & 0xFF);
    pkt[3] = (uint8_t)(seq & 0xFF);
    memcpy(pkt.data() + 4, enc.data(), enc.size());

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(SERVER_PORT);
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    memset(sa.sin_zero, 0, sizeof(sa.sin_zero));

    dlog(L"[send] 调用 sendto, pkt.size=%d", (int)pkt.size());
    int sent = sendto(app->sock, (const char *)pkt.data(),
                      (int)pkt.size(), 0, (sockaddr *)&sa, sizeof(sa));
    dlog(L"[send] sendto 返回=%d, err=%d", sent, WSAGetLastError());

    if (sent == SOCKET_ERROR) {
        wchar_t m[128];
        swprintf_s(m, L"!! sendto 失败: %d", WSAGetLastError());
        app->queue_log(m);
    } else {
        wchar_t m[600];
        swprintf_s(m, L">> #%u [%dB] %s", seq, (int)pkt.size(), text);
        app->queue_log(m);
    }
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_LOG: {
        if (wParam) {
            wchar_t *t = (wchar_t *)wParam;
            HWND hLog = g_app ? g_app->hLog : NULL;
            if (hLog) {
                int len = GetWindowTextLengthW(hLog);
                SendMessageW(hLog, EM_SETSEL, len, len);
                SendMessageW(hLog, EM_REPLACESEL, FALSE, (LPARAM)t);
                SendMessageW(hLog, EM_SETSEL, -1, -1);
                SendMessageW(hLog, EM_SCROLLCARET, 0, 0);
            }
            free(t);
        }
        return 0;
    }
    case WM_COMMAND: {
        WORD id = LOWORD(wParam);
        dlog(L"[wndproc] WM_COMMAND id=%d", id);
        if (id == 100) { // 发送按钮
            if (g_app && g_app->hInput) {
                int len = GetWindowTextLengthW(g_app->hInput);
                dlog(L"[wndproc] 输入长度=%d", len);
                if (len > 0) {
                    std::wstring buf((size_t)len + 1, L'\0');
                    GetWindowTextW(g_app->hInput, &buf[0], len + 1);
                    while (!buf.empty() && (buf.back() == L'\r' || buf.back() == L'\n')) buf.pop_back();
                    if (!buf.empty()) {
                        send_message(g_app, buf.c_str());
                        SetWindowTextW(g_app->hInput, L"");
                    }
                }
            }
            if (g_app) SetFocus(g_app->hInput);
        } else if (id == 201) {
            // EN_CHANGE from input box - ignore
        } else if (id == 101) {
            if (g_app && g_app->hLog) SetWindowTextW(g_app->hLog, L"");
        }
        return 0;  // 显式返回 0
    }
    case WM_SIZE: {
        if (!g_app) return 0;
        int W = LOWORD(lParam), H = HIWORD(lParam);
        int m = 10;
        int logH = H - m * 2 - 90 - 24;
        SetWindowPos(g_app->hLog, NULL, m, m, W - m * 2, logH, SWP_NOZORDER);
        SetWindowPos(g_app->hInput, NULL, m, m + logH + m, W - m * 2 - 90, 80, SWP_NOZORDER);
        SetWindowPos(g_app->hStatus, NULL, m, H - m - 24, W - m * 2, 24, SWP_NOZORDER);
        return 0;
    }
    case WM_DESTROY: {
        dlog(L"[wndproc] WM_DESTROY");
        if (g_app) g_app->cleanup();
        if (g_logHandle != INVALID_HANDLE_VALUE) { CloseHandle(g_logHandle); g_logHandle = INVALID_HANDLE_VALUE; }
        WSACleanup();
        PostQuitMessage(0);
        return 0;
    }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nShow) {
    open_log();
    dlog(L"[main] === 启动 ===");

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(NULL, (LPWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"linoh_chat_v4";
    if (!RegisterClassExW(&wc)) {
        dlog(L"[main] RegisterClass 失败");
        MessageBoxW(NULL, L"RegisterClass 失败", L"错误", MB_ICONERROR);
        return 1;
    }
    dlog(L"[main] class registered");

    HWND hwnd = CreateWindowExW(0, wc.lpszClassName,
        L"linoh 聊天 v4 [诊断版]",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
        760, 540, NULL, NULL, hInst, NULL);
    if (!hwnd) {
        dlog(L"[main] CreateWindow 失败");
        MessageBoxW(NULL, L"CreateWindow 失败", L"错误", MB_ICONERROR);
        return 1;
    }
    dlog(L"[main] window created");

    AppState state{};
    state.hwnd = hwnd;
    g_app = &state;

    state.hLog = CreateWindowW(L"EDIT", L"[诊断版] 正在初始化...\r\n",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY |
        WS_VSCROLL | ES_AUTOVSCROLL | WS_BORDER,
        10, 10, 720, 320, hwnd, (HMENU)200, hInst, NULL);

    state.hInput = CreateWindowW(L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE |
        WS_VSCROLL | ES_AUTOVSCROLL | WS_BORDER,
        10, 340, 630, 80, hwnd, (HMENU)201, hInst, NULL);

    HWND hBtnSend = CreateWindowW(L"BUTTON", L"发送 (Ctrl+Enter)",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        650, 355, 80, 32, hwnd, (HMENU)100, hInst, NULL);

    HWND hBtnClear = CreateWindowW(L"BUTTON", L"清空",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        650, 395, 80, 28, hwnd, (HMENU)101, hInst, NULL);

    state.hStatus = CreateWindowW(L"STATIC", L"状态: 启动中...",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        10, 480, 720, 24, hwnd, (HMENU)202, hInst, NULL);

    HFONT hFont = CreateFontW(-13, 0, 0, 0, FW_NORMAL, 0, 0, 0,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Consolas");
    SendMessageW(state.hLog, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessageW(state.hInput, WM_SETFONT, (WPARAM)hFont, TRUE);
    dlog(L"[main] child windows created");

    WSADATA wsa{};
    int wsaret = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (wsaret != 0) {
        dlog(L"[main] WSAStartup 失败: %d", wsaret);
        MessageBoxW(NULL, L"WSAStartup 失败", L"错误", MB_ICONERROR);
        return 1;
    }
    dlog(L"[main] WSAStartup OK");

    state.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (state.sock == INVALID_SOCKET) {
        dlog(L"[main] socket 失败: %d", WSAGetLastError());
        MessageBoxW(NULL, L"socket() 失败", L"错误", MB_ICONERROR);
        WSACleanup();
        return 1;
    }
    dlog(L"[main] sock=%d", (int)state.sock);

    state.tk = new HandshakeTokenKey(
        HandshakeTokenKey::from_bytes(std::span<const uint8_t>(DEMO_PSK, 32)));
    dlog(L"[main] tk created");

    SecretKey sk = SecretKey::generate();
    state.localId = sk.public_key();
    dlog(L"[main] localId=%s", utf16_from_utf8(state.localId.fmt_short()).c_str());

    state.running = true;
    state.hRecvThread = CreateThread(NULL, 0, recv_thread, &state, 0, NULL);
    dlog(L"[main] recv thread started");

    // 欢迎语
    g_app->queue_log(L"=== linoh 聊天 v4 [诊断] ===");
    g_app->queue_log(L"日志已写入 exe 同目录 chat_gui_v4_log.txt");
    g_app->queue_log(L"请确保 echo_server_winsock.exe 已启动");
    g_app->queue_log(L"-------------------------");

    dlog(L"[main] showing window");
    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);
    SetForegroundWindow(hwnd);  // 确保窗口在前台，可接收按钮点击

    MSG m{};
    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }

    dlog(L"[main] message loop exited, cleanup");
    g_app->cleanup();
    DeleteObject(hFont);
    dlog(L"[main] === 退出 ===");
    if (g_logHandle != INVALID_HANDLE_VALUE) { CloseHandle(g_logHandle); g_logHandle = INVALID_HANDLE_VALUE; }
    return (int)m.wParam;
}
