


#include <iostream>
#include <fstream>

#include "nlohmann/json.hpp"

#include "ConfigReader.hpp"


ConfigReader::ConfigReader(
    const std::filesystem::path& configFilePath
) : configFilePath(configFilePath) {
    jsonObject = parseJsonFile(configFilePath);
}


nlohmann::json ConfigReader::parseJsonFile(const std::filesystem::path& configFilePath)
{
    nlohmann::json jsonObject;
    try {
        // Read the JSON file
        std::ifstream configFile(configFilePath);

        if (!configFile.is_open()) {
            std::cerr << "Failed to open the file: " << configFilePath << std::endl;
            return 1;
        }
        configFile >> jsonObject;
        configFile.close();

        std::cout << "Successfully read the JSON file: " << configFilePath << std::endl;

    }
    catch (const std::ifstream::failure& e) {
        std::cerr << "Exception opening/reading/closing file: " << e.what() << std::endl;
        jsonObject = nullptr;
    }
    catch (const nlohmann::json::parse_error& e) {
        std::cerr << "JSON parsing error: " << e.what() << std::endl;
        jsonObject = nullptr;
    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        jsonObject = nullptr;
    }

    return jsonObject;
}

std::vector<std::pair<std::wstring, std::wstring>> ConfigReader::getPathQueryPairs()
{
    std::vector<std::pair<std::wstring, std::wstring>> pathQueryPairs;
    // Check if "event_processor" and "source" exist
    if (jsonObject.find("event_processor") != jsonObject.end() && 
        jsonObject["event_processor"].find("source") != jsonObject["event_processor"].end()) {
        auto sourceArray = jsonObject["event_processor"]["source"];

        // Iterate over the "source" array
        for (const auto& sourceObj : sourceArray) {
            // Check if "path" and "query" exist in sourceObj
            if (sourceObj.find("path") != sourceObj.end() && sourceObj.find("query") != sourceObj.end()) {
                std::string path = sourceObj["path"];
                std::wstring pwsPath = std::wstring(path.begin(), path.end());
                std::string query = sourceObj["query"];
                std::wstring pwsQuery = std::wstring(query.begin(), query.end());
                pathQueryPairs.push_back(std::make_pair(pwsPath, pwsQuery));
            } else {
                pathQueryPairs.clear();
                break;
            }
        }
    } else {
        pathQueryPairs.clear();
    }

    return pathQueryPairs;
}

std::string ConfigReader::getServerUri()
{
    if (jsonObject.find("uri") != jsonObject.end()) {
        return jsonObject["uri"];
    } else {
        // Handle missing "uri"
        // For example, log an error, throw an exception, or return a default value
        return ""; // Returning an empty string as an example
    }
}

std::string ConfigReader::getServerReverseShellIp()
{
    if (jsonObject.find("command_processor") != jsonObject.end() &&
        jsonObject["command_processor"].find("reverse_shell") != jsonObject["command_processor"].end()) {
        return jsonObject["command_processor"]["reverse_shell"]["ip"];
    } else {
        // Handle missing "command_processor" or "reverse_shell"
        // For example, log an error, throw an exception, or return a default value
        return ""; // Returning an empty string as an example
    }
}

int ConfigReader::getServerReverseShellPort()
{
    if (jsonObject.find("command_processor") != jsonObject.end() &&
        jsonObject["command_processor"].find("reverse_shell") != jsonObject["command_processor"].end()) {
        return jsonObject["command_processor"]["reverse_shell"]["port"];
    } else {
        // Handle missing "command_processor" or "reverse_shell"
        // For example, log an error, throw an exception, or return a default value
        return -1; // Returning -1 as an example
    }
}

