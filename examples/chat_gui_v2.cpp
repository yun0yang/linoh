// linoh 聊天测试端 (Win32 GUI) - 稳定版
// - 子线程仅操作日志队列(无HWND)
// - 主线程用 WM_TIMER 每 100ms 刷新日志
// - 标准 WS_OVERLAPPEDWINDOW 样式
#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// 强制使用 winsock2.h，阻止 winsock.h 被第三方头间接引入
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
#include <mutex>
#include <thread>
#include <atomic>

using namespace linoh;
using namespace linoh::tls;
using namespace linoh::base;

static constexpr uint16_t SERVER_PORT = 54321;
static constexpr UINT     WM_APPEND_LOG = WM_USER + 100;

static const uint8_t DEMO_PSK[32] = {
    0x6c, 0x69, 0x6e, 0x6f, 0x68, 0x2d, 0x64, 0x65,
    0x6d, 0x6f, 0x2d, 0x70, 0x73, 0x6b, 0x2d, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x30
};
static const char *AD_STR = "linoh-echo-demo";
static constexpr size_t AD_LEN = 13;

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

// ---------- 全局状态（主窗口创建后才填充） ----------
struct AppState {
    HWND hwnd = nullptr;
    HWND hLog = nullptr;
    HWND hInput = nullptr;
    HWND hStatus = nullptr;
    SOCKET sock = INVALID_SOCKET;
    sockaddr_in serverAddr = {};
    EndpointId localId;
    std::atomic<uint32_t> nextSeq{1};
    std::atomic<bool> running{true};
    std::thread recvThread;
    // tk 用堆分配，避免默认构造问题
    HandshakeTokenKey *tk = nullptr;

    // 线程安全日志队列
    std::mutex logMutex;
    std::vector<std::wstring> logQueue;

    void append_log(const std::wstring &s) {
        std::lock_guard<std::mutex> lk(logMutex);
        logQueue.push_back(s);
    }
    std::vector<std::wstring> drain() {
        std::lock_guard<std::mutex> lk(logMutex);
        std::vector<std::wstring> r;
        r.swap(logQueue);
        return r;
    }
};
static AppState *g_app = nullptr;

// ---------- Append line to EDIT control ----------
static void edit_append(HWND hEdit, const wchar_t *text) {
    if (!hEdit) return;
    int n = GetWindowTextLengthW(hEdit);
    SendMessageW(hEdit, EM_SETSEL, n, n);
    SendMessageW(hEdit, EM_REPLACESEL, FALSE, (LPARAM)text);
    int len2 = GetWindowTextLengthW(hEdit);
    SendMessageW(hEdit, EM_SETSEL, len2, len2);
    SendMessageW(hEdit, EM_SCROLLCARET, 0, 0);
}

// ---------- AEAD 发送消息 ----------
static void send_message(AppState *app, const wchar_t *text) {
    std::string msg = utf8_from_utf16(std::wstring(text));
    if (msg.empty()) {
        app->append_log(L"!! 空消息未发送");
        return;
    }
    uint32_t seq = app->nextSeq.fetch_add(1);

    auto enc = app->tk->seal(seq,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(AD_STR), AD_LEN),
        std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(msg.data()), msg.size()));
    if (enc.empty()) {
        app->append_log(L"!! AEAD 加密失败");
        return;
    }

    std::vector<uint8_t> pkt(4 + enc.size());
    pkt[0] = static_cast<uint8_t>((seq >> 24) & 0xFF);
    pkt[1] = static_cast<uint8_t>((seq >> 16) & 0xFF);
    pkt[2] = static_cast<uint8_t>((seq >> 8) & 0xFF);
    pkt[3] = static_cast<uint8_t>(seq & 0xFF);
    memcpy(pkt.data() + 4, enc.data(), enc.size());

    int sent = sendto(app->sock, reinterpret_cast<const char *>(pkt.data()),
                      static_cast<int>(pkt.size()), 0,
                      reinterpret_cast<sockaddr *>(&app->serverAddr),
                      sizeof(app->serverAddr));
    if (sent == SOCKET_ERROR) {
        app->append_log(L"!! sendto 失败: " + std::to_wstring(WSAGetLastError()));
        return;
    }
    app->append_log(L">> #" + std::to_wstring(seq) + L" [" + std::to_wstring(pkt.size()) +
                    L"B] " + std::wstring(text));
}

// ---------- 收包线程 ----------
static void recv_loop(AppState *app) {
    std::vector<uint8_t> buf(8192);
    while (app->running) {
        sockaddr_in from{};
        int fromlen = sizeof(from);
        int n = recvfrom(app->sock, reinterpret_cast<char *>(buf.data()),
                         static_cast<int>(buf.size()), 0,
                         reinterpret_cast<sockaddr *>(&from), &fromlen);
        if (n == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT || err == 10060) continue;
            if (!app->running) break;
            app->append_log(L"!! recvfrom 失败: " + std::to_wstring(err));
            continue;
        }
        if (n < 4) continue;

        uint32_t rseq = (static_cast<uint32_t>(buf[0]) << 24) |
                        (static_cast<uint32_t>(buf[1]) << 16) |
                        (static_cast<uint32_t>(buf[2]) << 8) |
                        static_cast<uint32_t>(buf[3]);

        auto dec = app->tk->open(rseq,
            std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(AD_STR), AD_LEN),
            std::span<const uint8_t>(buf.data() + 4, n - 4));
        if (dec.empty()) {
            app->append_log(L"!! AEAD 解密失败 (seq=" + std::to_wstring(rseq) + L")");
            continue;
        }
        std::string reply(reinterpret_cast<char *>(dec.data()), dec.size());
        app->append_log(L"<< #" + std::to_wstring(rseq) + L" " + utf16_from_utf8(reply));
    }
}

// ---------- 窗口过程 ----------
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        // 注意：WM_CREATE 里不要启动线程或做大量 IO，先返回成功
        return 0;
    }
    case WM_TIMER: {
        // 定时将日志队列中的内容追加到 UI
        if (g_app && g_app->hLog) {
            auto batch = g_app->drain();
            for (auto &s : batch) {
                edit_append(g_app->hLog, (s + L"\r\n").c_str());
            }
        }
        return 0;
    }
    case WM_COMMAND: {
        WORD id = LOWORD(wParam);
        if (id == 100) { // 发送按钮
            if (g_app && g_app->hInput) {
                int len = GetWindowTextLengthW(g_app->hInput);
                if (len > 0) {
                    std::wstring buf(static_cast<size_t>(len) + 1, L'\0');
                    GetWindowTextW(g_app->hInput, &buf[0], len + 1);
                    if (!buf.empty()) {
                        send_message(g_app, buf.c_str());
                        SetWindowTextW(g_app->hInput, L"");
                    }
                }
            }
            SetFocus(g_app ? g_app->hInput : NULL);
        } else if (id == 101) { // 清空
            if (g_app && g_app->hLog) SetWindowTextW(g_app->hLog, L"");
        } else if (id == 203) { // 输入框回车
            // Ctrl+Enter 发送
            if (GetAsyncKeyState(VK_CONTROL) & 0x8000) {
                SendMessageW(hwnd, WM_COMMAND, 100, 0);
            }
        }
        break;
    }
    case WM_SIZE: {
        int W = LOWORD(lParam), H = HIWORD(lParam);
        if (g_app) {
            int margin = 10;
            int logH = H - margin * 2 - 90 - 24;
            int inputY = margin + logH + margin;
            SetWindowPos(g_app->hLog, NULL, margin, margin, W - margin * 2, logH, SWP_NOZORDER);
            SetWindowPos(g_app->hInput, NULL, margin, inputY, W - margin * 2 - 90, 80, SWP_NOZORDER);
            SetWindowPos(g_app->hStatus, NULL, margin, H - margin - 24, W - margin * 2, 24, SWP_NOZORDER);
        }
        return 0;
    }
    case WM_DESTROY: {
        if (g_app) {
            g_app->running = false;
            if (g_app->recvThread.joinable()) g_app->recvThread.join();
            if (g_app->sock != INVALID_SOCKET) {
                closesocket(g_app->sock);
                g_app->sock = INVALID_SOCKET;
            }
            delete g_app->tk;
            g_app->tk = nullptr;
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
    // 预先注册窗口类
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(NULL, (LPWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"linoh_chat_v2";
    wc.style = CS_HREDRAW | CS_VREDRAW;

    if (!RegisterClassExW(&wc)) {
        DWORD err = GetLastError();
        wchar_t buf[256];
        swprintf_s(buf, L"RegisterClass 失败，错误=%u", err);
        MessageBoxW(NULL, buf, L"linoh 聊天", MB_ICONERROR);
        return 1;
    }

    // 先创建主窗口（不含复杂子控件）
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName,
        L"linoh 聊天测试 - WinSock2 + AEAD",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
        760, 540, NULL, NULL, hInst, NULL);
    if (!hwnd) {
        DWORD err = GetLastError();
        wchar_t buf[256];
        swprintf_s(buf, L"CreateWindow 失败，错误=%u", err);
        MessageBoxW(NULL, buf, L"linoh 聊天", MB_ICONERROR);
        return 1;
    }

    // 初始化应用状态
    AppState state;
    state.hwnd = hwnd;
    g_app = &state;

    // 创建子控件（标准 EDIT，不依赖 richedit）
    state.hLog = CreateWindowW(L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY |
        WS_VSCROLL | ES_AUTOVSCROLL | WS_BORDER | ES_LEFT,
        10, 10, 720, 300, hwnd, (HMENU)200, hInst, NULL);

    state.hInput = CreateWindowW(L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE |
        WS_VSCROLL | ES_AUTOVSCROLL | WS_BORDER | ES_LEFT,
        10, 320, 620, 80, hwnd, (HMENU)201, hInst, NULL);

    HWND hBtnSend = CreateWindowW(L"BUTTON", L"发送 (Ctrl+Enter)",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        640, 330, 100, 32, hwnd, (HMENU)100, hInst, NULL);

    HWND hBtnClear = CreateWindowW(L"BUTTON", L"清空日志",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        640, 370, 100, 28, hwnd, (HMENU)101, hInst, NULL);

    state.hStatus = CreateWindowW(L"STATIC", L"状态: 初始化中...",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        10, 480, 720, 24, hwnd, (HMENU)202, hInst, NULL);

    HFONT hFont = CreateFontW(-13, 0, 0, 0, FW_NORMAL, 0, 0, 0,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Consolas");
    HFONT hFontBtn = CreateFontW(-13, 0, 0, 0, FW_NORMAL, 0, 0, 0,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei");

    SendMessageW(state.hLog, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessageW(state.hInput, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessageW(hBtnSend, WM_SETFONT, (WPARAM)hFontBtn, TRUE);
    SendMessageW(hBtnClear, WM_SETFONT, (WPARAM)hFontBtn, TRUE);
    SendMessageW(state.hStatus, WM_SETFONT, (WPARAM)hFontBtn, TRUE);

    // 启动定时器（每 100ms 刷新一次日志队列）
    SetTimer(hwnd, 1, 100, NULL);

    // 初始化 socket (在窗口就绪后才做)
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        SetWindowTextW(state.hStatus, L"状态: WSAStartup 失败");
        edit_append(state.hLog, L"!! WSAStartup 失败\r\n");
    } else {
        state.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (state.sock == INVALID_SOCKET) {
            wchar_t buf[128];
            swprintf_s(buf, L"!! socket() 失败: %d\r\n", WSAGetLastError());
            edit_append(state.hLog, buf);
            SetWindowTextW(state.hStatus, L"状态: socket 创建失败");
        } else {
            int to = 2000;
            setsockopt(state.sock, SOL_SOCKET, SO_RCVTIMEO,
                       reinterpret_cast<char *>(&to), sizeof(to));

            state.serverAddr.sin_family = AF_INET;
            state.serverAddr.sin_port = htons(SERVER_PORT);
            inet_pton(AF_INET, "127.0.0.1", &state.serverAddr.sin_addr);

            state.tk = new HandshakeTokenKey(HandshakeTokenKey::from_bytes(
                std::span<const uint8_t>(DEMO_PSK, 32)));

            SecretKey sk = SecretKey::generate();
            state.localId = sk.public_key();

            std::wstring status = L"已连接 127.0.0.1:" + std::to_wstring(SERVER_PORT)
                + L"  |  本地节点: " + utf16_from_utf8(state.localId.fmt_short());
            SetWindowTextW(state.hStatus, status.c_str());

            edit_append(state.hLog, L"=== linoh 聊天测试端 ===\r\n");
            edit_append(state.hLog, L"协议: UDP + ChaCha20-Poly1305 AEAD\r\n");
            edit_append(state.hLog, L"服务器: 127.0.0.1:54321\r\n");
            edit_append(state.hLog, L"请确保 echo_server_winsock.exe 已启动\r\n");
            edit_append(state.hLog, L"输入文字后点「发送」按钮\r\n");
            edit_append(state.hLog, L"-------------------------\r\n");

            // 启动收包线程（窗口已就绪）
            state.recvThread = std::thread(recv_loop, &state);
        }
    }

    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);

    MSG msg{};
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
