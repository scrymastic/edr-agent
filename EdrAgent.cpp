
#include "WebSocketClient.hpp"
#include "ConfigReader.hpp"

#include "pugixml.hpp"

#include <Windows.h>
#include <winevt.h>
#pragma comment(lib, "wevtapi.lib")

#include <iostream>
#include <locale>
#include <conio.h>


DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, 
                                PVOID pContext, EVT_HANDLE hEvent);
DWORD ProcessEvent(EVT_HANDLE hEvent);
DWORD EventToEventXml(EVT_HANDLE hEvent, std::string& eventXml);
std::string EventXmlToEventJson(const std::string& xml);
std::string sanitizeUtf8(const std::string& input);

WebSocketClient* g_client = nullptr;


int main() {
    std::cout << "Reading configuration file" << std::endl;

    ConfigReader configReader("config.json");
    std::vector<std::pair<std::wstring, std::wstring>> pathQueryPairs = configReader.getPathQueryPairs();
    std::string serverUri = configReader.getServerUri();

    std::cout << "Connecting to server: " << serverUri << std::endl;
    WebSocketClient client;
    g_client = &client;
    client.connect(serverUri);

    // Send hello message
    // client.send("Hello from EDR Agent");

    // Sleep for 5 seconds
    std::this_thread::sleep_for(std::chrono::seconds(5));

    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hSubscription = NULL;

    for (const auto& pair : pathQueryPairs)
    {
        std::wcout << L"Subscribing to channel: " << std::endl;
        std::wstring pwsPath = pair.first;
        std::wstring pwsQuery = pair.second;
        std::wcout << L"Path: " << pwsPath << L", Query: " << pwsQuery << std::endl;

        hSubscription = EvtSubscribe(NULL, NULL, pwsPath.c_str(), pwsQuery.c_str(), NULL, NULL,
            (EVT_SUBSCRIBE_CALLBACK)SubscriptionCallback, EvtSubscribeToFutureEvents);

        if (NULL == hSubscription)
        {
            status = GetLastError();

            if (ERROR_EVT_CHANNEL_NOT_FOUND == status)
                std::wcout << L"The channel \"" << pwsPath << L"\" was not found.\n";
            else if (ERROR_EVT_INVALID_QUERY == status)
                // You can call EvtGetExtendedStatus to get information as to why the query is not valid.
                std::wcout << L"The query \"" << pwsQuery << L"\" is not valid.\n";
            else
                std::wcout << L"EvtSubscribe failed with " << status << L"\n";

            goto cleanup;
        }
    }

    std::cout << "Agent is running..." << std::endl;

    wprintf(L"Hit any key to quit\n\n");
    while (!_kbhit())
        Sleep(10);

cleanup:

    if (hSubscription)
        EvtClose(hSubscription);
    
    client.close();

    return status;
}


DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent)
{
    UNREFERENCED_PARAMETER(pContext);

    DWORD status = ERROR_SUCCESS;

    switch (action)
    {
        // You should only get the EvtSubscribeActionError action if your subscription flags
        // includes EvtSubscribeStrict and the channel contains missing event records.
    case EvtSubscribeActionError:
        if (ERROR_EVT_QUERY_RESULT_STALE == (DWORD)hEvent)
        {
            std::wcout << L"The subscription callback was notified that event records are missing.\n";
            // Handle if this is an issue for your application.
        }
        else
        {
            std::wcout << L"The subscription callback received the following error: " << (DWORD)hEvent << L"\n";
        }
        break;

    case EvtSubscribeActionDeliver:
        if (ERROR_SUCCESS != (status = ProcessEvent(hEvent)))
        {
            goto cleanup;
        }
        break;

    default:
        std::wcout << L"SubscriptionCallback: Unknown action.\n";
        break;
    }

cleanup:

    if (ERROR_SUCCESS != status)
    {
        // End subscription - Use some kind of IPC mechanism to signal
        // your application to close the subscription handle.
    }

    return status; // The service ignores the returned status.
}


// Render the event as an XML string and print it.
DWORD ProcessEvent(EVT_HANDLE hEvent)
{
    DWORD status = ERROR_SUCCESS;
    std::string eventXml;
    std::string json;

    status = EventToEventXml(hEvent, eventXml);

    if (status != ERROR_SUCCESS)
    {
        std::cout << "Failed to render event as XML" << std::endl;
        goto cleanup;
    }

    // std::cout << eventXml << std::endl;

    // Sanitize the XML string to remove invalid UTF-8 characters
    eventXml = sanitizeUtf8(eventXml);
    
    json = EventXmlToEventJson(eventXml);
    // std::cout << json << std::endl;

    g_client->send(json);
    std::cout << "Sent event to server" << std::endl;

cleanup:
    if (hEvent)
        EvtClose(hEvent);

    return status;
}



DWORD EventToEventXml(EVT_HANDLE hEvent, std::string& eventXml)
{
    DWORD status = ERROR_SUCCESS;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    std::vector<WCHAR> pContent;

    if (!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pContent.data(), &dwBufferUsed, &dwPropertyCount))
    {
        if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
        {
            dwBufferSize = dwBufferUsed;
            pContent.resize(dwBufferSize, 0);
            if (pContent.data())
            {
                EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pContent.data(), &dwBufferUsed, &dwPropertyCount);
            }
            else
            {
                std::wcout << L"Failed to allocate memory for rendering the event.\n";
                status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }
        }

        if (ERROR_SUCCESS != (status = GetLastError()))
        {
            std::wcout << L"EvtRender failed with " << status << L"\n";
            goto cleanup;
        }
    }

    eventXml = std::string(pContent.begin(), pContent.end());

cleanup:
    if (pContent.data())
        pContent.clear();

    return status;
}


std::string EventXmlToEventJson(const std::string& xml)
{
    try
    {
        pugi::xml_document doc;
        pugi::xml_parse_result result = doc.load_string(xml.c_str());

        if (!result)
        {
            return "";
        }

        nlohmann::json systemJson;
        nlohmann::json eventDataJson;
        nlohmann::json eventJson;

        for (pugi::xml_node node : doc.child("Event").children())
        {
            if (std::string(node.name()) == "System")
            {
                for (pugi::xml_node child : node.children())
                {
                    std::string nodeName = child.name();
                    if (nodeName == "Channel")
                    {
                        systemJson["Channel"] = child.text().as_string();
                    }
                    else if (nodeName == "Computer")
                    {
                        systemJson["Computer"] = child.text().as_string();
                    }
                    else if (nodeName == "Correlation") {
                        systemJson["Correlation"] = nlohmann::json::object();
                        if (child.attribute("ActivityID")) {
                            systemJson["Correlation"]["ActivityID"] = child.attribute("ActivityID").value();
                        }
                        if (child.attribute("RelatedActivityID")) {
                            systemJson["Correlation"]["RelatedActivityID"] = child.attribute("RelatedActivityID").value();
                        }
                    }
                    else if (nodeName == "EventID")
                    {
                        systemJson["EventID"] = child.text().as_int();
                    }
                    else if (nodeName == "EventRecordID")
                    {
                        systemJson["EventRecordID"] = child.text().as_int();
                    }
                    else if (nodeName == "Execution")
                    {
                        systemJson["Execution"]["ProcessID"] = child.attribute("ProcessID").as_int();
                        systemJson["Execution"]["ThreadID"] = child.attribute("ThreadID").as_int();
                    }
                    else if (nodeName == "Keywords")
                    {
                        systemJson["Keywords"] = child.text().as_string();
                    }
                    else if (nodeName == "Level")
                    {
                        systemJson["Level"] = child.text().as_int();
                    }
                    else if (nodeName == "Opcode")
                    {
                        systemJson["Opcode"] = child.text().as_int();
                    }
                    else if (nodeName == "Provider")
                    {
                        systemJson["Provider"]["Name"] = child.attribute("Name").value();
                        systemJson["Provider"]["Guid"] = child.attribute("Guid").value();
                    }
                    else if (nodeName == "Security")
                    {
                        systemJson["Security"]["UserID"] = child.attribute("UserID").value();
                    }
                    else if (nodeName == "Task")
                    {
                        systemJson["Task"] = child.text().as_int();
                    }
                    else if (nodeName == "TimeCreated")
                    {
                        systemJson["TimeCreated"]["SystemTime"] = child.attribute("SystemTime").value();
                    }
                    else if (nodeName == "Version")
                    {
                        systemJson["Version"] = child.text().as_int();
                    }
                    else
                    {
                        systemJson[child.name()] = child.text().as_string();
                    }
                }

            }
            else if (std::string(node.name()) == "EventData")
            {
                for (pugi::xml_node child : node.children())
                {
                    std::string nodeAttr = child.attribute("Name").value();
                    if (nodeAttr == "DestinationPort") {
                        eventDataJson["DestinationPort"] = child.text().as_int();
                    }
                    else if (nodeAttr == "SourcePort") {
                        eventDataJson["SourcePort"] = child.text().as_int();
                    }
                    else if (nodeAttr == "ProcessId") {
                        eventDataJson["ProcessId"] = child.text().as_int();
                    }
                    else if (nodeAttr == "TerminalSessionId") {
                        eventDataJson["TerminalSessionId"] = child.text().as_int();
                    }
                    else {
                        eventDataJson[nodeAttr] = child.text().as_string();
                    }
                }
            }
        }

        eventJson["type"] = "event";
        eventJson["info"]["System"] = systemJson;
        eventJson["info"]["EventData"] = eventDataJson;

        return eventJson.dump(4);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error in EventXmlToEventJson: " << e.what() << std::endl;
        std::cerr << "XML: " << xml << std::endl;
        return "";
    }
}


std::string sanitizeUtf8(const std::string& input) 
{
    std::string output;
    output.reserve(input.length());

    for (size_t i = 0; i < input.length(); i++) 
    {
        unsigned char c = input[i];
        if (c < 0x80) 
        {
            // ASCII character
            output.push_back(c);
        } 
        else if ((c & 0xE0) == 0xC0) 
        {
            // 2-byte UTF-8 sequence
            if (i + 1 < input.length() && (input[i + 1] & 0xC0) == 0x80) 
            {
                output.push_back(c);
                output.push_back(input[++i]);
            }
        } 
        else if ((c & 0xF0) == 0xE0) 
        {
            // 3-byte UTF-8 sequence
            if (i + 2 < input.length() && (input[i + 1] & 0xC0) == 0x80 && (input[i + 2] & 0xC0) == 0x80) 
            {
                output.push_back(c);
                output.push_back(input[++i]);
                output.push_back(input[++i]);
            }
        } 
        else if ((c & 0xF8) == 0xF0) 
        {
            // 4-byte UTF-8 sequence
            if (i + 3 < input.length() && (input[i + 1] & 0xC0) == 0x80 && (input[i + 2] & 0xC0) == 0x80 && (input[i + 3] & 0xC0) == 0x80) 
            {
                output.push_back(c);
                output.push_back(input[++i]);
                output.push_back(input[++i]);
                output.push_back(input[++i]);
            }
        }
        else
        {
            std::cerr << "Invalid UTF-8 character: " << c << std::endl;
        }
    }

    return output;
}


