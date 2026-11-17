/// linoh 聊天测试端 (Win32 GUI)
///   - WinSock2 UDP + AEAD 加密与 echo_server_winsock 通信
///   - 收发消息实时显示在日志框中，支持中文 UTF-8
///   - Ctrl+Enter 发送，Enter 换行
///
/// 协议: [4B seq BE][ChaCha20-Poly1305 AEAD(plaintext)]
///       与 echo_server_winsock.exe 配套使用

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/base/key.hpp"
#include "linoh/tls/handshake_token_key.hpp"

#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <chrono>

using namespace linoh;
using namespace linoh::tls;
using namespace linoh::base;

// =====================================================================
// 协议常量
// =====================================================================
static constexpr uint16_t SERVER_PORT  = 54321;
static constexpr size_t   MAX_PKT     = 2048;
static constexpr size_t   SEQ_SIZE    = 4;
static const uint8_t      DEMO_PSK[32] = {
    0x6c, 0x69, 0x6e, 0x6f, 0x68, 0x2d, 0x64, 0x65,
    0x6d, 0x6f, 0x2d, 0x70, 0x73, 0x6b, 0x2d, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x30
};
static const char *AD_STR = "linoh-echo-demo";

// =====================================================================
// AppState
// =====================================================================
struct AppState {
    HWND           hwndMain    = nullptr;
    HWND           hEditLog    = nullptr;   // 消息日志（只读）
    HWND           hEditInput  = nullptr;   // 输入框
    HWND           hBtnSend    = nullptr;   // 发送按钮
    HWND           hBtnClear   = nullptr;   // 清空按钮
    HWND           hStatus     = nullptr;   // 状态栏
    SOCKET         sock        = INVALID_SOCKET;
    sockaddr_in     serverAddr  = {};
    HandshakeTokenKey tk;
    EndpointId     localId;
    std::atomic<uint32_t> nextSeq{1};
    std::atomic<bool> connected{false};
    std::atomic<bool> running{true};

    std::thread recvThread;
    std::thread uiThread;

    // 待追加到日志的条目 (color: 0=普通, 1=发送, 2=接收, 3=错误)
    struct LogEntry { std::wstring text; int color; };
    std::vector<LogEntry> pendingLog;
    std::mutex pendingMutex;
    std::condition_variable pendingCv;

    void add_log(const std::wstring &text, int color);
    void start_recv();
    void stop();
    void send_message(const wchar_t *text);
};

// =====================================================================
// 工具函数
// =====================================================================

static std::string utf8_from_utf16(const wchar_t *s) {
    if (!s) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, s, -1, nullptr, 0, nullptr, nullptr);
    if (len == 0) return {};
    std::string r(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s, -1, r.data(), len, nullptr, nullptr);
    return r;
}

static std::wstring utf16_from_utf8(const char *s) {
    if (!s) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    if (len == 0) return {};
    std::wstring r(len - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s, -1, r.data(), len);
    return r;
}

static void append_to_edit(HWND hEdit, const wchar_t *text) {
    SendMessageW(hEdit, EM_SETSEL, -1, -1);
    SendMessageW(hEdit, EM_REPLACESEL, FALSE, (LPARAM)text);
    SendMessageW(hEdit, EM_SCROLLCARET, 0, 0);
}

static void append_line(HWND hEdit, const wchar_t *line) {
    std::wstring s(line);
    s += L"\r\n";
    append_to_edit(hEdit, s.c_str());
}

// =====================================================================
// AppState 方法
// =====================================================================

void AppState::add_log(const std::wstring &text, int color) {
    std::lock_guard<std::mutex> lk(pendingMutex);
    pendingLog.push_back({text, color});
    pendingCv.notify_one();
}

void AppState::start_recv() {
    recvThread = std::thread([this]() {
        std::vector<uint8_t> buf(MAX_PKT);
        while (running) {
            if (sock == INVALID_SOCKET) {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                continue;
            }
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(sock, &rfds);
            timeval tv{0, 50000}; // 50ms timeout
            int ret = select(0, &rfds, nullptr, nullptr, &tv);
            if (ret <= 0) continue;

            sockaddr_in from{};
            int fromlen = sizeof(from);
            int n = recvfrom(sock, (char*)buf.data(), (int)buf.size(), 0,
                             (sockaddr*)&from, &fromlen);
            if (n <= 0) continue;
            if ((size_t)n < SEQ_SIZE) continue;

            uint32_t reply_seq =
                (uint32_t(buf[0]) << 24) |
                (uint32_t(buf[1]) << 16) |
                (uint32_t(buf[2]) << 8) |
                uint32_t(buf[3]);

            std::span<const uint8_t> ct(buf.data() + SEQ_SIZE, n - SEQ_SIZE);

            std::span<const uint8_t> ad_bytes((const uint8_t*)AD_STR, strlen(AD_STR));
            auto dec = tk.open(reply_seq, ad_bytes, ct);
            if (dec.empty()) {
                add_log(L"[错误] AEAD 解密失败 (seq=" + std::to_wstring(reply_seq) + L")", 3);
                continue;
            }

            std::string pt((char*)dec.data(), dec.size());
            std::wstring line = L"[服务器] #" + std::to_wstring(reply_seq) + L": " + utf16_from_utf8(pt.c_str());
            add_log(line, 2);
        }
    });

    // UI 更新线程（每秒批量刷新 pending log 到控件）
    uiThread = std::thread([this]() {
        while (running) {
            std::vector<LogEntry> batch;
            {
                std::unique_lock<std::mutex> lk(pendingMutex);
                pendingCv.wait_for(lk, std::chrono::seconds(1), [this] {
                    return !pendingLog.empty() || !running;
                });
                if (!running) break;
                batch.swap(pendingLog);
            }
            if (!batch.empty() && hEditLog) {
                for (const auto &e : batch) {
                    std::wstring line;
                    if (e.color == 1) line = L">> " + e.text;     // 发送
                    else if (e.color == 2) line = L"<< " + e.text;  // 接收
                    else if (e.color == 3) line = L"!! " + e.text; // 错误
                    else line = e.text;
                    append_line(hEditLog, line.c_str());
                }
            }
        }
    });
}

void AppState::stop() {
    running = false;
    pendingCv.notify_all();
    if (recvThread.joinable()) recvThread.join();
    if (uiThread.joinable()) uiThread.join();
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
        sock = INVALID_SOCKET;
    }
}

void AppState::send_message(const wchar_t *text) {
    if (!text || !connected) return;
    std::string msg_utf8 = utf8_from_utf16(text);
    if (msg_utf8.empty()) return;

    uint32_t seq = nextSeq.fetch_add(1);

    std::span<const uint8_t> ad_bytes((const uint8_t*)AD_STR, strlen(AD_STR));
    auto enc = tk.seal(seq, ad_bytes,
                       std::span<const uint8_t>((const uint8_t*)msg_utf8.data(), msg_utf8.size()));
    if (enc.empty()) {
        add_log(L"[错误] AEAD 加密失败", 3);
        return;
    }

    std::vector<uint8_t> pkt(SEQ_SIZE + enc.size());
    pkt[0] = (uint8_t)((seq >> 24) & 0xFF);
    pkt[1] = (uint8_t)((seq >> 16) & 0xFF);
    pkt[2] = (uint8_t)((seq >> 8) & 0xFF);
    pkt[3] = (uint8_t)(seq & 0xFF);
    memcpy(pkt.data() + SEQ_SIZE, enc.data(), enc.size());

    int sent = sendto(sock, (const char*)pkt.data(), (int)pkt.size(), 0,
                      (sockaddr*)&serverAddr, sizeof(serverAddr));
    if (sent == SOCKET_ERROR) {
        add_log(L"[错误] sendto 失败: " + std::to_wstring(WSAGetLastError()), 3);
    } else {
        add_log(L"[发送] #" + std::to_wstring(seq) + L": " + std::wstring(text), 1);
    }
}

// =====================================================================
// 窗口过程
// =====================================================================
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static AppState *app = nullptr;

    switch (msg) {
    case WM_CREATE: {
        LPCREATESTRUCTW cs = (LPCREATESTRUCTW)lParam;
        app = (AppState*)cs->lpCreateParams;
        app->hwndMain = hwnd;

        int W = 680, H = 520;
        int m = 16;
        int logH = H - m * 2 - 80 - 36 - m - 24;
        int inputY = m + logH + m;
        int btnY = inputY + 80 + 4;
        int statusY = H - m - 24;

        HFONT hFont = CreateFontW(-13, 0, 0, 0, FW_NORMAL, 0, 0, 0,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Consolas");
        HFONT hFontBtn = CreateFontW(-13, 0, 0, 0, FW_NORMAL, 0, 0, 0,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei");

        // 消息日志（只读）
        app->hEditLog = CreateWindowW(L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY |
            WS_VSCROLL | WS_HSCROLL | ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_BORDER,
            m, m, W - m * 2, logH, hwnd, (HMENU)200, GetModuleHandleW(nullptr), nullptr);

        // 输入框
        app->hEditInput = CreateWindowW(L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE |
            WS_VSCROLL | ES_AUTOVSCROLL | WS_BORDER,
            m, inputY, W - m * 2 - 90, 80, hwnd, (HMENU)201, GetModuleHandleW(nullptr), nullptr);

        // 发送按钮
        app->hBtnSend = CreateWindowW(L"BUTTON", L"发送 (Ctrl+Enter)",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            W - m - 82, btnY, 82, 28,
            hwnd, (HMENU)100, GetModuleHandleW(nullptr), nullptr);

        // 清空日志按钮
        app->hBtnClear = CreateWindowW(L"BUTTON", L"清空",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            W - m - 82, btnY + 34, 82, 28,
            hwnd, (HMENU)101, GetModuleHandleW(nullptr), nullptr);

        // 状态栏
        app->hStatus = CreateWindowW(L"STATIC",
            L"状态: 初始化中...",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            m, statusY, W - m * 2, 24,
            hwnd, (HMENU)202, GetModuleHandleW(nullptr), nullptr);

        // 设置字体
        SendMessageW(app->hEditLog, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(app->hEditInput, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(app->hBtnSend, WM_SETFONT, (WPARAM)hFontBtn, TRUE);
        SendMessageW(app->hBtnClear, WM_SETFONT, (WPARAM)hFontBtn, TRUE);
        SendMessageW(app->hStatus, WM_SETFONT, (WPARAM)hFontBtn, TRUE);

        SetFocus(app->hEditInput);

        // ---- Winsock 初始化 ----
        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            SetWindowTextW(app->hStatus, L"状态: WSAStartup 失败");
            break;
        }

        app->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (app->sock == INVALID_SOCKET) {
            SetWindowTextW(app->hStatus, L"状态: socket() 失败");
            WSACleanup();
            break;
        }

        int timeout = 100;
        setsockopt(app->sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

        app->serverAddr.sin_family = AF_INET;
        app->serverAddr.sin_port = htons(SERVER_PORT);
        InetPtonW(AF_INET, L"127.0.0.1", &app->serverAddr.sin_addr);

        app->tk = HandshakeTokenKey::from_bytes(std::span<const uint8_t>(DEMO_PSK, 32));

        SecretKey sk = SecretKey::generate();
        app->localId = sk.public_key();

        app->connected = true;
        app->start_recv();

        std::wstring status = L"已连接 127.0.0.1:" + std::to_wstring(SERVER_PORT)
            + L"  |  本地 ID: " + utf16_from_utf8(app->localId.fmt_short().c_str());
        SetWindowTextW(app->hStatus, status.c_str());

        // 欢迎语
        append_line(app->hEditLog, L"=== linoh 聊天测试端 ===");
        append_line(app->hEditLog, L"协议: UDP + ChaCha20-Poly1305 AEAD");
        append_line(app->hEditLog, L"服务器: 127.0.0.1:54321");
        append_line(app->hEditLog, L"请确保 echo_server_winsock.exe 已启动");
        append_line(app->hEditLog, L"输入文字后按「发送」或 Ctrl+Enter 发送");
        append_line(app->hEditLog, L"=========================");
        return 0;
    }

    case WM_COMMAND: {
        if (LOWORD(wParam) == 100) { // 发送按钮
            HWND hInput = app->hEditInput;
            int len = GetWindowTextLengthW(hInput);
            if (len > 0) {
                std::wstring buf(len + 1, L'\0');
                GetWindowTextW(hInput, buf.data(), len + 1);
                // 去掉末尾换行
                while (!buf.empty() && (buf.back() == L'\r' || buf.back() == L'\n')) {
                    buf.pop_back();
                }
                if (!buf.empty()) {
                    app->send_message(buf.c_str());
                    SetWindowTextW(hInput, L"");
                }
            }
            SetFocus(hInput);
        } else if (LOWORD(wParam) == 101) { // 清空按钮
            SetWindowTextW(app->hEditLog, L"");
        }
        break;
    }

    case WM_KEYDOWN: {
        if (wParam == VK_RETURN && (GetAsyncKeyState(VK_CONTROL) & 0x8000)) {
            SendMessageW(hwnd, WM_COMMAND, 100, 0);
        }
        break;
    }

    case WM_SIZE: {
        if (!app) break;
        int W = LOWORD(lParam), H = HIWORD(lParam);
        int m = 16;
        int logH = H - m * 2 - 80 - 36 - m - 24;
        int inputY = m + logH + m;
        int btnY = inputY + 80 + 4;
        int statusY = H - m - 24;

        SetWindowPos(app->hEditLog, nullptr, m, m, W - m * 2, logH, SWP_NOZORDER);
        SetWindowPos(app->hEditInput, nullptr, m, inputY, W - m * 2 - 90, 80, SWP_NOZORDER);
        SetWindowPos(app->hBtnSend, nullptr, W - m - 82, btnY, 82, 28, SWP_NOZORDER);
        SetWindowPos(app->hBtnClear, nullptr, W - m - 82, btnY + 34, 82, 28, SWP_NOZORDER);
        SetWindowPos(app->hStatus, nullptr, m, statusY, W - m * 2, 24, SWP_NOZORDER);
        break;
    }

    case WM_DESTROY: {
        if (app) {
            app->stop();
            WSACleanup();
        }
        PostQuitMessage(0);
        return 0;
    }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// =====================================================================
// WinMain
// =====================================================================
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nShow) {
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(nullptr, (LPWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"linoh_chat_win32";

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(nullptr, L"RegisterClass 失败", L"错误", MB_ICONERROR);
        return 1;
    }

    HWND hwnd = CreateWindowExW(0, wc.lpszClassName,
        L"linoh 聊天 - WinSock2 + AEAD",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 720, 560,
        nullptr, nullptr, hInst, nullptr);

    if (!hwnd) {
        MessageBoxW(nullptr, L"CreateWindow 失败", L"错误", MB_ICONERROR);
        return 1;
    }

    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
