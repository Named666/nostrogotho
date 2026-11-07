// uWebSockets reference server for benchmarking only (not part of the relay).
// uws_ref <port> <threads> echo|broadcast
#include "App.h"
#include <thread>
#include <vector>
#include <cstring>
int main(int argc, char **argv) {
    int port = argc > 1 ? atoi(argv[1]) : 9001;
    int nt = argc > 2 ? atoi(argv[2]) : 1;
    bool bc = argc > 3 && !strcmp(argv[3], "broadcast");
    struct PSD {};
    std::vector<std::thread> th;
    for (int i = 0; i < nt; i++) th.emplace_back([=]() {
        uWS::App *app = new uWS::App();
        app->ws<PSD>("/*", {
            .compression = uWS::DISABLED,
            .maxPayloadLength = 16 * 1024 * 1024,
            .idleTimeout = 120,
            .maxBackpressure = 64 * 1024 * 1024,
            .closeOnBackpressureLimit = false,
            .resetIdleTimeoutOnSend = false,
            .sendPingsAutomatically = true,
            .open = [bc](auto *ws) { if (bc) ws->subscribe("b"); },
            .message = [bc, app](auto *ws, std::string_view m, uWS::OpCode op) {
                if (bc) app->publish("b", m, op); else ws->send(m, op);
            },
        }).listen(port, [](auto *ls) { if (!ls) { fprintf(stderr, "listen failed\n"); exit(1); } }).run();
    });
    for (auto &t : th) t.join();
}
