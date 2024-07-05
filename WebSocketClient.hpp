

#ifndef WEBSOCKETCLIENT_HPP
#define WEBSOCKETCLIENT_HPP

#include "CommandProcessor.hpp"
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include "websocketpp/config/asio_no_tls_client.hpp"
#include "websocketpp/client.hpp"

typedef websocketpp::client<websocketpp::config::asio_client> client;

class WebSocketClient {
public:
    WebSocketClient();
    void connect(const std::string& uri);
    void send(const std::string& data);
    void close();

private:
    void on_open(websocketpp::connection_hdl hdl);
    void on_message(websocketpp::connection_hdl, client::message_ptr msg);
    void on_close(websocketpp::connection_hdl);
    void on_fail(websocketpp::connection_hdl);

    client m_client;
    websocketpp::connection_hdl m_hdl;
    bool m_open;
    std::thread m_client_thread;
    std::mutex m_mutex;
    std::condition_variable m_cv;
};

#endif // WEBSOCKETCLIENT_HPP