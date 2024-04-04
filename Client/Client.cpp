// Client.cpp
//Name: Tom Shtern; ID: 318783289
//State: spaghetti code Not Finale, Did Not Finish In Time.............................................


#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <mutex>
#include <boost/asio.hpp>
#include "ChecksumWrapper.h"
#include "cksum_new.cpp"
#include "AESWrapper.h"
#include "RSAWrapper.h"

class Client {
public:
    Client(const std::string& configFile);
    void run();

private:
    bool loadConfiguration(const std::string& configFile);
    bool connectToServer();
    bool authenticate();
    bool exchangeKeys();
    bool encryptAndSendFile(const std::string& filePath);
    void sendEncryptedData(const std::vector<uint8_t>& data);
    std::vector<uint8_t> receiveData();
    void savePrivateKey();
    void loadPrivateKey();
    bool resumeInterruptedTransfer(const std::string& filePath);
    void updateProgress(int progress);
    void transferFile(const std::string& filePath);
    std::string generateClientID();

    boost::asio::io_context m_ioContext;
    boost::asio::ip::tcp::socket m_socket;
    RSAPrivateWrapper m_privateKey;
    RSAPublicWrapper m_serverPublicKey;
    AESWrapper m_aesWrapper;
    std::string m_serverIP;
    int m_serverPort;
    std::string m_username;
    std::string m_password;
    std::string m_clientID;
    std::mutex m_mutex;
};

Client::Client(const std::string& configFile)
    : m_socket(m_ioContext)
{
    if (!loadConfiguration(configFile)) {
        throw std::runtime_error("Failed to load configuration.");
    }
    loadPrivateKey();
}

void Client::run()
{
    try {
        std::cout << "Connecting to the server..." << std::endl;
        if (!connectToServer()) {
            std::cerr << "Failed to connect to the server. Retrying in 5 seconds..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(5));
            if (!connectToServer()) {
                std::cerr << "Failed to connect to the server after retry. Exiting." << std::endl;
                return;
            }
        }

        std::cout << "Authenticating with the server..." << std::endl;
        if (!authenticate()) {
            std::cerr << "Failed to authenticate with the server. Exiting." << std::endl;
            return;
        }

        std::cout << "Exchanging keys with the server..." << std::endl;
        if (!exchangeKeys()) {
            std::cerr << "Failed to exchange keys with the server. Exiting." << std::endl;
            return;
        }

        std::ifstream infoFile("transfer.info");
        if (!infoFile) {
            std::cerr << "Failed to open transfer.info file." << std::endl;
            return;
        }

        std::vector<std::thread> transferThreads;
        std::string filePath;
        while (std::getline(infoFile, filePath)) {
            transferThreads.emplace_back(&Client::transferFile, this, filePath);
        }

        for (auto& thread : transferThreads) {
            thread.join();
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
}

bool Client::loadConfiguration(const std::string& configFile)
{
    std::ifstream config(configFile);
    if (!config) {
        std::cerr << "Failed to open configuration file: " << configFile << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(config, line)) {
        std::istringstream iss(line);
        std::string key, value;
        if (std::getline(iss, key, '=') && std::getline(iss, value)) {
            if (key == "ServerIP") {
                boost::system::error_code ec;
                boost::asio::ip::address::from_string(value, ec);
                if (ec) {
                    std::cerr << "Invalid ServerIP: " << value << std::endl;
                    return false;
                }
                m_serverIP = value;
            }
            else if (key == "ServerPort") {
                int port = std::stoi(value);
                if (port < 1 || port > 65535) {
                    std::cerr << "Invalid ServerPort: " << value << std::endl;
                    return false;
                }
                m_serverPort = port;
            }
            else if (key == "Username") {
                m_username = value;
            }
            else if (key == "Password") {
                m_password = value;
            }
        }
    }

    if (m_serverIP.empty() || m_serverPort == 0 || m_username.empty() || m_password.empty()) {
        std::cerr << "Missing required configuration values." << std::endl;
        return false;
    }

    return true;
}

bool Client::connectToServer()
{
    try {
        boost::asio::ip::tcp::resolver resolver(m_ioContext);
        boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(m_serverIP, std::to_string(m_serverPort));
        boost::asio::connect(m_socket, endpoints);
        std::cout << "Connected to server." << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Failed to connect to server: " << e.what() << std::endl;
        return false;
    }
}

bool Client::authenticate()
{
    try {
        m_clientID = generateClientID();

        std::string authData = m_username + ":" + m_password + ":" + m_clientID;
        sendEncryptedData(std::vector<uint8_t>(authData.begin(), authData.end()));

        std::vector<uint8_t> authResult = receiveData();
        std::string authResultStr(authResult.begin(), authResult.end());

        if (authResultStr == "success") {
            std::cout << "Authentication successful." << std::endl;
            return true;
        }
        else {
            std::cerr << "Authentication failed." << std::endl;
            return false;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Failed to authenticate: " << e.what() << std::endl;
        return false;
    }
}

bool Client::exchangeKeys()
{
    try {
        if (m_privateKey.getPrivateKey().empty()) {
            m_privateKey = RSAPrivateWrapper();
            savePrivateKey();
        }

        std::string publicKeyString = m_privateKey.getPublicKey();
        sendEncryptedData(std::vector<uint8_t>(publicKeyString.begin(), publicKeyString.end()));

        std::vector<uint8_t> serverPublicKeyData = receiveData();
        std::string serverPublicKeyString(serverPublicKeyData.begin(), serverPublicKeyData.end());
        m_serverPublicKey = RSAPublicWrapper(serverPublicKeyString.c_str(), serverPublicKeyString.length());

        unsigned char aesKey[AESWrapper::DEFAULT_KEYLENGTH];
        AESWrapper::GenerateKey(aesKey, AESWrapper::DEFAULT_KEYLENGTH);
        m_aesWrapper = AESWrapper(aesKey, AESWrapper::DEFAULT_KEYLENGTH);

        std::string encryptedAesKey = m_serverPublicKey.encrypt(reinterpret_cast<const char*>(aesKey), AESWrapper::DEFAULT_KEYLENGTH);
        sendEncryptedData(std::vector<uint8_t>(encryptedAesKey.begin(), encryptedAesKey.end()));

        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Failed to exchange keys: " << e.what() << std::endl;
        return false;
    }
}

bool Client::encryptAndSendFile(const std::string& filePath)
{
    try {
        std::ifstream inputFile(filePath, std::ios::binary);
        if (!inputFile) {
            std::cerr << "Failed to open file: " << filePath << std::endl;
            return false;
        }

        std::vector<uint8_t> fileContent((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
        inputFile.close();

        std::string checksum = ChecksumWrapper::calculateChecksum(std::string(fileContent.begin(), fileContent.end()));

        std::string encryptedContent = m_aesWrapper.encrypt(reinterpret_cast<const char*>(fileContent.data()), fileContent.size());

        sendEncryptedData(std::vector<uint8_t>(encryptedContent.begin(), encryptedContent.end()));
        sendEncryptedData(std::vector<uint8_t>(checksum.begin(), checksum.end()));

        std::cout << "File sent successfully: " << filePath << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Failed to encrypt and send file: " << filePath << ". Error: " << e.what() << std::endl;
        return false;
    }
}

void Client::sendEncryptedData(const std::vector<uint8_t>& data)
{
    try {
        std::vector<uint8_t> littleEndianData(data.rbegin(), data.rend());

        uint32_t dataSize = static_cast<uint32_t>(littleEndianData.size());
        boost::asio::write(m_socket, boost::asio::buffer(&dataSize, sizeof(dataSize)));
        boost::asio::write(m_socket, boost::asio::buffer(littleEndianData));
    }
    catch (const std::exception& e) {
        throw std::runtime_error("Failed to send encrypted data: " + std::string(e.what()));
    }
}

std::vector<uint8_t> Client::receiveData()
{
    try {
        uint32_t dataSize;
        boost::asio::read(m_socket, boost::asio::buffer(&dataSize, sizeof(dataSize)));

        std::vector<uint8_t> data(dataSize);
        boost::asio::read(m_socket, boost::asio::buffer(data));

        std::vector<uint8_t> bigEndianData(data.rbegin(), data.rend());

        return bigEndianData;
    }
    catch (const std::exception& e) {
        throw std::runtime_error("Failed to receive data: " + std::string(e.what()));
    }
}

void Client::savePrivateKey()
{
    try {
        std::ofstream privKeyFile("priv.key");
        privKeyFile << m_privateKey.getPrivateKey();
    }
    catch (const std::exception& e) {
        std::cerr << "Failed to save private key: " << e.what() << std::endl;
    }
}

void Client::loadPrivateKey()
{
    try {
        std::ifstream privKeyFile("priv.key");
        std::string privateKeyString((std::istreambuf_iterator<char>(privKeyFile)), std::istreambuf_iterator<char>());
        m_privateKey = RSAPrivateWrapper(privateKeyString.c_str(), privateKeyString.length());
    }
    catch (const std::exception& e) {
        std::cerr << "Failed to load private key: " << e.what() << std::endl;
    }
}

bool Client::resumeInterruptedTransfer(const std::string& filePath)
{
    try {
        std::ifstream resumeFile(filePath + ".resume");
        if (!resumeFile) {
            return false;
        }

        uint64_t resumeOffset;
        resumeFile >> resumeOffset;
        resumeFile.close();

        std::ifstream inputFile(filePath, std::ios::binary);
        if (!inputFile) {
            std::cerr << "Failed to open file: " << filePath << std::endl;
            return false;
        }

        inputFile.seekg(resumeOffset);

        std::vector<uint8_t> fileContent((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
        inputFile.close();

        std::string checksum = ChecksumWrapper::calculateChecksum(std::string(fileContent.begin(), fileContent.end()));

        std::string encryptedContent = m_aesWrapper.encrypt(reinterpret_cast<const char*>(fileContent.data()), fileContent.size());

        sendEncryptedData(std::vector<uint8_t>(encryptedContent.begin(), encryptedContent.end()));
        sendEncryptedData(std::vector<uint8_t>(checksum.begin(), checksum.end()));

        std::cout << "Resumed file transfer: " << filePath << std::endl;

        std::remove((filePath + ".resume").c_str());

        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Failed to resume file transfer: " << filePath << ". Error: " << e.what() << std::endl;
        return false;
    }
}

void Client::updateProgress(int progress)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::cout << "\rProgress: " << progress << "%" << std::flush;
}

void Client::transferFile(const std::string& filePath)
{
    std::cout << "Transferring file: " << filePath << std::endl;
    if (!resumeInterruptedTransfer(filePath)) {
        if (!encryptAndSendFile(filePath)) {
            std::cerr << "Failed to encrypt and send file: " << filePath << std::endl;
        }
    }
}

std::string Client::generateClientID()
{
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    auto randomNum = std::rand();
    std::ostringstream oss;
    oss << timestamp << "_" << randomNum;
    return oss.str();
}

int main() {
    try {
        Client client("client.conf");
        client.run();
    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    return 0;
}

