

#include "WebSocketClient.hpp"
#include <websocketpp/config/asio_no_tls_client.hpp>
#include <websocketpp/client.hpp>
#include <iostream>
#include <stdexcept>

using websocketpp::lib::bind;
using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;

WebSocketClient::WebSocketClient() : m_open(false) {
    try {
        m_client.clear_access_channels(websocketpp::log::alevel::all);
        m_client.set_access_channels(websocketpp::log::alevel::connect | websocketpp::log::alevel::disconnect);
        m_client.clear_error_channels(websocketpp::log::elevel::all);
        m_client.set_error_channels(websocketpp::log::elevel::fatal);

        m_client.init_asio();
        m_client.set_open_handler(bind(&WebSocketClient::on_open, this, _1));
        m_client.set_message_handler(bind(&WebSocketClient::on_message, this, _1, _2));
        m_client.set_close_handler(bind(&WebSocketClient::on_close, this, _1));
        m_client.set_fail_handler(bind(&WebSocketClient::on_fail, this, _1));
    } catch (const std::exception& e) {
        std::cerr << "Error in WebSocketClient constructor: " << e.what() << std::endl;
        throw;
    }
}

void WebSocketClient::connect(const std::string& uri) {
    try {
        websocketpp::lib::error_code ec;
        client::connection_ptr con = m_client.get_connection(uri, ec);
        if (ec) {
            std::cerr << "Could not create connection because: " << ec.message() << std::endl;
            return;
        }
        m_client.connect(con);
        m_client_thread = std::thread([this]() {
            try {
                m_client.run();
            } catch (const std::exception& e) {
                std::cerr << "Error in client thread: " << e.what() << std::endl;
            }
        });
    } catch (const std::exception& e) {
        std::cerr << "Error in connect: " << e.what() << std::endl;
    }
}

void WebSocketClient::send(const std::string& data) {
    try {
        std::unique_lock lock(m_mutex);
        if (!m_cv.wait_for(lock, std::chrono::seconds(10), [this]() { return m_open; })) {
            throw std::runtime_error("Connection timeout");
        }
        if (!m_open) {
            throw std::runtime_error("Connection is not open");
        }
        if (data.empty()) {
            std::cerr << "Data is empty" << std::endl;
            return;
        }
        websocketpp::lib::error_code ec;
        m_client.send(m_hdl, data, websocketpp::frame::opcode::text, ec);
        if (ec) {
            std::cerr << "Error sending message: " << ec.message() << std::endl;
            return;
        }
        // std::cout << "Sent data: " << data << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error in send: " << e.what() << std::endl;
    }
}

void WebSocketClient::close() {
    try {
        m_client.stop();
        if (m_client_thread.joinable()) {
            m_client_thread.join();
        }
    } catch (const std::exception& e) {
        std::cerr << "Error in close: " << e.what() << std::endl;
    }
}

void WebSocketClient::on_open(websocketpp::connection_hdl hdl) {
    try {
        std::lock_guard lock(m_mutex);
        m_open = true;
        m_hdl = hdl;
        std::cout << "Connection opened" << std::endl;
        m_cv.notify_all();
    } catch (const std::exception& e) {
        std::cerr << "Error in on_open: " << e.what() << std::endl;
    }
}

void WebSocketClient::on_message(websocketpp::connection_hdl, client::message_ptr msg) {
    try {
        std::string command = msg->get_payload();
        std::cout << "Received command: " << command << std::endl;
        std::string response = CommandProcessor::executeCommand(command);
        if (!response.empty()) {
            send(response);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error in on_message: " << e.what() << std::endl;
    }
}

void WebSocketClient::on_close(websocketpp::connection_hdl) {
    try {
        std::lock_guard lock(m_mutex);
        m_open = false;
        std::cout << "Connection closed" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error in on_close: " << e.what() << std::endl;
    }
}

void WebSocketClient::on_fail(websocketpp::connection_hdl) {
    try {
        std::lock_guard lock(m_mutex);
        m_open = false;
        std::cerr << "Connection failed" << std::endl;
        // Exit the program
        std::cout << "Exiting the program" << std::endl;
        exit(1);
    } catch (const std::exception& e) {
        std::cerr << "Error in on_fail: " << e.what() << std::endl;
    }
}