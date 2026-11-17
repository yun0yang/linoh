// linoh 聊天测试端 (Win32 GUI) v3 - 诊断版
// 解决卡死: recv_thread 不持有 logMutex，只 PostMessage 到主线程
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

using namespace linoh;
using namespace linoh::tls;
using namespace linoh::base;

static constexpr uint16_t SERVER_PORT = 54321;
static constexpr UINT     WM_LOG     = WM_USER + 1;
static constexpr UINT     WM_STATUS  = WM_USER + 2;
static constexpr UINT     WM_ERROR   = WM_USER + 3;

static const uint8_t DEMO_PSK[32] = {
    0x6c, 0x69, 0x6e, 0x6f, 0x68, 0x2d, 0x64, 0x65,
    0x6d, 0x6f, 0x2d, 0x70, 0x73, 0x6b, 0x2d, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x30
};
static const char *AD_STR = "linoh-echo-demo";
static constexpr size_t AD_LEN = 13;

// ---------- 日志消息结构（通过 WM_COPYDATA 传递） ----------
struct LogMsg {
    enum Kind { KSend, KRecv, KError, KInfo };
    Kind kind;
    wchar_t text[512];
};

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

// ---------- AppState ----------
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
    std::vector<std::wstring> recvQueue;  // 收包结果，仅主线程访问
    HANDLE hRecvThread = NULL;

    void queue_log(LogMsg::Kind kind, const wchar_t *msg) {
        if (!hwnd) return;
        LogMsg *m = new LogMsg();
        m->kind = kind;
        wcsncpy_s(m->text, msg, _TRUNCATE);
        PostMessageW(hwnd, WM_LOG, (WPARAM)m, 0);
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

// ---------- 收包线程 ----------
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
        timeval tv{0, 200000}; // 200ms poll

        int ret = select(0, &rfds, NULL, NULL, &tv);
        if (ret <= 0) continue;
        if (!app->running) break;

        int n = recvfrom(app->sock, (char *)buf, sizeof(buf), 0, NULL, NULL);
        if (n == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT) continue;
            wchar_t msg[128];
            swprintf_s(msg, L"recvfrom 错误: %d", err);
            app->queue_log(LogMsg::KError, msg);
            break;
        }
        if (n < 4) continue;

        uint32_t rseq = (DWORD(buf[0]) << 24) |
                        (DWORD(buf[1]) << 16) |
                        (DWORD(buf[2]) << 8) |
                        DWORD(buf[3]);

        auto dec = app->tk->open(rseq,
            std::span<const uint8_t>((const uint8_t *)AD_STR, AD_LEN),
            std::span<const uint8_t>(buf + 4, n - 4));
        if (dec.empty()) {
            wchar_t msg[128];
            swprintf_s(msg, L"AEAD 解密失败 (seq=%u)", rseq);
            app->queue_log(LogMsg::KError, msg);
            continue;
        }
        std::string reply((char *)dec.data(), dec.size());
        wchar_t msg[600];
        swprintf_s(msg, L"<< #%u %s", rseq, utf16_from_utf8(reply).c_str());
        app->queue_log(LogMsg::KRecv, msg);
    }
    return 0;
}

// ---------- 发送消息 ----------
static void send_message(AppState *app, const wchar_t *text) {
    if (!text || !app->tk) return;
    std::string msg = utf8_from_utf16(std::wstring(text));
    if (msg.empty()) return;

    uint32_t seq = app->nextSeq.fetch_add(1);

    auto enc = app->tk->seal(seq,
        std::span<const uint8_t>((const uint8_t *)AD_STR, AD_LEN),
        std::span<const uint8_t>((const uint8_t *)msg.data(), msg.size()));
    if (enc.empty()) {
        app->queue_log(LogMsg::KError, L"AEAD 加密失败");
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
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);

    int sent = sendto(app->sock, (const char *)pkt.data(),
                      (int)pkt.size(), 0, (sockaddr *)&sa, sizeof(sa));
    if (sent == SOCKET_ERROR) {
        wchar_t msg[128];
        swprintf_s(msg, L"sendto 失败: %d", WSAGetLastError());
        app->queue_log(LogMsg::KError, msg);
        return;
    }
    wchar_t sendbuf[600];
    swprintf_s(sendbuf, L">> #%u [%dB] %s", seq, (int)pkt.size(), text);
    app->queue_log(LogMsg::KSend, sendbuf);
}

// ---------- 窗口过程 ----------
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        OutputDebugStringW(L"[DBG] WM_CREATE\n");
        return 0;
    }
    case WM_LOG: {
        // wParam 是 LogMsg*
        if (wParam == 0) break;
        LogMsg *m = (LogMsg *)wParam;
        HWND hLog = g_app ? g_app->hLog : NULL;
        if (hLog) {
            int len = GetWindowTextLengthW(hLog);
            SendMessageW(hLog, EM_SETSEL, len, len);
            SendMessageW(hLog, EM_REPLACESEL, FALSE, (LPARAM)m->text);
            SendMessageW(hLog, EM_SETSEL, -1, -1);
            SendMessageW(hLog, EM_SCROLLCARET, 0, 0);
        }
        delete m;
        return 0;
    }
    case WM_STATUS: {
        if (g_app && g_app->hStatus) {
            SetWindowTextW(g_app->hStatus, (LPCWSTR)wParam);
        }
        return 0;
    }
    case WM_ERROR: {
        MessageBoxW(hwnd, (LPCWSTR)wParam, L"错误", MB_ICONERROR);
        return 0;
    }
    case WM_COMMAND: {
        WORD id = LOWORD(wParam);
        if (id == 100) { // 发送
            if (g_app && g_app->hInput) {
                int len = GetWindowTextLengthW(g_app->hInput);
                if (len > 0) {
                    std::wstring buf((size_t)len + 1, L'\0');
                    GetWindowTextW(g_app->hInput, &buf[0], len + 1);
                    // 去掉末尾换行
                    while (!buf.empty() && (buf.back() == L'\r' || buf.back() == L'\n')) {
                        buf.pop_back();
                    }
                    if (!buf.empty()) {
                        send_message(g_app, buf.c_str());
                        SetWindowTextW(g_app->hInput, L"");
                    }
                }
            }
            if (g_app) SetFocus(g_app->hInput);
        } else if (id == 101) { // 清空
            if (g_app && g_app->hLog) SetWindowTextW(g_app->hLog, L"");
        }
        return 0;
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
        OutputDebugStringW(L"[DBG] WM_DESTROY\n");
        if (g_app) {
            g_app->running = false;
            if (g_app->sock != INVALID_SOCKET) {
                closesocket(g_app->sock);
                g_app->sock = INVALID_SOCKET;
            }
            if (g_app->hRecvThread) {
                WaitForSingleObject(g_app->hRecvThread, 2000);
                CloseHandle(g_app->hRecvThread);
                g_app->hRecvThread = NULL;
            }
            delete g_app->tk;
            g_app->tk = NULL;
            WSACleanup();
        }
        PostQuitMessage(0);
        return 0;
    }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// ---------- WinMain ----------
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nShow) {
    OutputDebugStringW(L"[DBG] WinMain start\n");

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(NULL, (LPWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"linoh_chat_v3";
    if (!RegisterClassExW(&wc)) {
        MessageBoxW(NULL, L"RegisterClass 失败", L"错误", MB_ICONERROR);
        return 1;
    }
    OutputDebugStringW(L"[DBG] class registered\n");

    HWND hwnd = CreateWindowExW(0, wc.lpszClassName,
        L"linoh 聊天 - WinSock2 + AEAD",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
        760, 540, NULL, NULL, hInst, NULL);
    if (!hwnd) {
        MessageBoxW(NULL, L"CreateWindow 失败", L"错误", MB_ICONERROR);
        return 1;
    }
    OutputDebugStringW(L"[DBG] window created\n");

    AppState state{};
    state.hwnd = hwnd;
    g_app = &state;

    // 子控件
    state.hLog = CreateWindowW(L"EDIT", L"正在初始化...\r\n",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY |
        WS_VSCROLL | ES_AUTOVSCROLL | WS_BORDER,
        10, 10, 720, 320, hwnd, (HMENU)200, hInst, NULL);

    state.hInput = CreateWindowW(L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE |
        WS_VSCROLL | ES_AUTOVSCROLL | WS_BORDER,
        10, 340, 630, 80, hwnd, (HMENU)201, hInst, NULL);

    HWND hBtnSend = CreateWindowW(L"BUTTON", L"发送",
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
    OutputDebugStringW(L"[DBG] child windows created\n");

    // Winsock
    WSADATA wsa{};
    int wsaret = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (wsaret != 0) {
        wchar_t msg[128];
        swprintf_s(msg, L"WSAStartup 失败: %d", wsaret);
        PostMessageW(hwnd, WM_ERROR, (WPARAM)_wcsdup(msg), 0);
        return 1;
    }
    OutputDebugStringW(L"[DBG] WSAStartup OK\n");

    state.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (state.sock == INVALID_SOCKET) {
        wchar_t msg[128];
        swprintf_s(msg, L"socket() 失败: %d", WSAGetLastError());
        PostMessageW(hwnd, WM_ERROR, (WPARAM)_wcsdup(msg), 0);
        WSACleanup();
        return 1;
    }
    OutputDebugStringW(L"[DBG] socket created\n");

    // AEAD key
    state.tk = new HandshakeTokenKey(
        HandshakeTokenKey::from_bytes(std::span<const uint8_t>(DEMO_PSK, 32)));
    OutputDebugStringW(L"[DBG] tk created\n");

    SecretKey sk = SecretKey::generate();
    state.localId = sk.public_key();
    OutputDebugStringW(L"[DBG] key generated\n");

    // 启动收包线程
    state.running = true;
    state.hRecvThread = CreateThread(NULL, 0, recv_thread, &state, 0, NULL);
    OutputDebugStringW(L"[DBG] recv thread started\n");

    // 状态栏
    std::wstring status = L"已就绪  127.0.0.1:" + std::to_wstring(SERVER_PORT)
        + L"  节点:" + utf16_from_utf8(state.localId.fmt_short());
    PostMessageW(hwnd, WM_STATUS, (WPARAM)_wcsdup(status.c_str()), 0);

    // 欢迎语
    g_app->queue_log(LogMsg::KInfo, L"=== linoh 聊天测试端 v3 ===");
    g_app->queue_log(LogMsg::KInfo, L"协议: UDP + ChaCha20-Poly1305 AEAD");
    g_app->queue_log(LogMsg::KInfo, L"服务器: 127.0.0.1:54321");
    g_app->queue_log(LogMsg::KInfo, L"请先启动 echo_server_winsock.exe");
    g_app->queue_log(LogMsg::KInfo, L"输入文字后点「发送」或按 Ctrl+Enter");
    g_app->queue_log(LogMsg::KInfo, L"-------------------------");

    OutputDebugStringW(L"[DBG] showing window\n");
    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);
    OutputDebugStringW(L"[DBG] entering message loop\n");

    MSG m{};
    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    OutputDebugStringW(L"[DBG] message loop exited\n");

    g_app->cleanup();
    DeleteObject(hFont);
    return (int)m.wParam;
}
