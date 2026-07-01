/*
 * Password Manager Tool - C++ Version (OpenSSL Only)
 * Compile: g++ -std=c++17 password.cpp -o password -lssl -lcrypto
 * Cross-compile for Windows: x86_64-w64-mingw32-g++ -std=c++17 password.cpp -o password.exe -I${OPENSSL_DIR}/include -L${OPENSSL_DIR}/lib64 -lssl -lcrypto -static -static-libgcc -static-libstdc++ -lws2_32 -lcrypt32
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <sstream>
#include <algorithm>
#include <cstring>

// OpenSSL
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace fs = std::filesystem;

// ANSI Color codes
namespace Colors {
    const std::string RESET = "\033[0m";
    const std::string BOLD = "\033[1m";
    const std::string RED = "\033[91m";
    const std::string GREEN = "\033[92m";
    const std::string YELLOW = "\033[93m";
    const std::string BLUE = "\033[94m";
    const std::string CYAN = "\033[96m";
    const std::string MAGENTA = "\033[95m";
    const std::string GRAY = "\033[90m";
}

// Simple JSON parser and generator (to avoid external dependencies)
class SimpleJSON {
public:
    std::map<std::string, std::vector<std::pair<std::string, std::string>>> data;

    std::string escape(const std::string& str) const {
        std::string result;
        for (char c : str) {
            if (c == '"' || c == '\\') result += '\\';
            result += c;
        }
        return result;
    }

    std::string unescape(const std::string& str) {
        std::string result;
        bool escaped = false;
        for (char c : str) {
            if (escaped) {
                result += c;
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else {
                result += c;
            }
        }
        return result;
    }

    std::string toString() const {
        std::ostringstream oss;
        oss << "{\n";
        bool first_key = true;
        for (const auto& [key, entries] : data) {
            if (!first_key) oss << ",\n";
            first_key = false;
            oss << "  \"" << escape(key) << "\": [\n";
            bool first_entry = true;
            for (const auto& [username, password] : entries) {
                if (!first_entry) oss << ",\n";
                first_entry = false;
                oss << "    {\n";
                oss << "      \"username\": \"" << escape(username) << "\",\n";
                oss << "      \"password\": \"" << escape(password) << "\"\n";
                oss << "    }";
            }
            oss << "\n  ]";
        }
        oss << "\n}\n";
        return oss.str();
    }

    bool parse(const std::string& json) {
        // Simple JSON parser (only handles our format)
        data.clear();
        std::string current_key;
        std::string current_username;
        std::string current_password;

        size_t pos = 0;
        while (pos < json.length()) {
            // Skip whitespace
            while (pos < json.length() && std::isspace(json[pos])) pos++;
            if (pos >= json.length()) break;

            // Find key
            if (json[pos] == '"') {
                pos++;
                size_t end = json.find('"', pos);
                if (end == std::string::npos) break;
                std::string key = unescape(json.substr(pos, end - pos));
                pos = end + 1;

                // Skip to :
                while (pos < json.length() && json[pos] != ':') pos++;
                pos++;

                // Skip whitespace
                while (pos < json.length() && std::isspace(json[pos])) pos++;

                // Check if array
                if (json[pos] == '[') {
                    current_key = key;
                    pos++;
                } else if (json[pos] == '"') {
                    // String value
                    pos++;
                    size_t end = json.find('"', pos);
                    if (end == std::string::npos) break;
                    std::string value = unescape(json.substr(pos, end - pos));
                    pos = end + 1;

                    if (key == "username") {
                        current_username = value;
                    } else if (key == "password") {
                        current_password = value;
                        if (!current_key.empty() && !current_username.empty()) {
                            data[current_key].push_back({current_username, current_password});
                            current_username.clear();
                            current_password.clear();
                        }
                    }
                }
            } else {
                pos++;
            }
        }
        return true;
    }
};

class PasswordManager {
private:
    fs::path home_dir;
    fs::path ssh_dir;
    fs::path passwd_file;
    fs::path ssh_key_path;
    std::vector<unsigned char> master_key;

    // OpenSSL AES-256-CBC encryption
    std::vector<unsigned char> aes_encrypt(const std::vector<unsigned char>& plaintext,
                                            const std::vector<unsigned char>& key,
                                            const std::vector<unsigned char>& iv) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
        int len, ciphertext_len;

        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        ciphertext_len += len;
        EVP_CIPHER_CTX_free(ctx);

        ciphertext.resize(ciphertext_len);
        return ciphertext;
    }

    std::vector<unsigned char> aes_decrypt(const std::vector<unsigned char>& ciphertext,
                                            const std::vector<unsigned char>& key,
                                            const std::vector<unsigned char>& iv) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        std::vector<unsigned char> plaintext(ciphertext.size());
        int len, plaintext_len;

        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
        plaintext_len = len;
        EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
        plaintext_len += len;
        EVP_CIPHER_CTX_free(ctx);

        plaintext.resize(plaintext_len);
        return plaintext;
    }

    std::vector<unsigned char> sha256(const std::string& input) {
        std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
        SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash.data());
        return hash;
    }

    std::vector<unsigned char> get_salt() {
        // Use a fixed salt derived from a known string for simplicity
        std::string salt_string = "hello3x3";
        auto full_hash = sha256(salt_string);
        std::vector<unsigned char> salt(16);
        std::copy(full_hash.begin(), full_hash.begin() + 16, salt.begin());
        return salt;
    }

    std::string get_master_password() {
        // Try to read SSH private key
        if (fs::exists(ssh_key_path)) {
            std::ifstream file(ssh_key_path, std::ios::binary);
            std::string content((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
            std::cout << Colors::GREEN << "✓ Using SSH key authentication: " << ssh_key_path
                     << Colors::RESET << std::endl;
            return content;
        }

        // If no SSH key, prompt user
        std::cout << Colors::YELLOW << "Note: SSH private key not found: " << ssh_key_path
                 << Colors::RESET << std::endl;
        std::cout << "You can:" << std::endl;
        std::cout << "  1. Generate SSH key: ssh-keygen -t ed25519" << std::endl;
        std::cout << "  2. Manually enter master password (required each time)" << std::endl;
        std::cout << std::endl;

        std::string password;
        std::cout << "Enter master password: ";
        std::getline(std::cin, password);

        if (password.empty()) {
            std::cerr << Colors::RED << "Error: Master password cannot be empty"
                     << Colors::RESET << std::endl;
            exit(1);
        }
        return password;
    }

    void init_encryption() {
        std::string master_password = get_master_password();
        master_key = sha256(master_password);
    }

    SimpleJSON load_data() {
        SimpleJSON json;
        if (!fs::exists(passwd_file)) {
            return json;
        }

        std::ifstream file(passwd_file, std::ios::binary);
        std::vector<unsigned char> encrypted_data((std::istreambuf_iterator<char>(file)),
                                                    std::istreambuf_iterator<char>());

        if (encrypted_data.empty()) {
            return json;
        }

        try {
            // First 16 bytes are IV
            std::vector<unsigned char> iv(encrypted_data.begin(), encrypted_data.begin() + 16);
            std::vector<unsigned char> ciphertext(encrypted_data.begin() + 16, encrypted_data.end());
            auto decrypted = aes_decrypt(ciphertext, master_key, iv);
            std::string json_str(decrypted.begin(), decrypted.end());
            json.parse(json_str);
        } catch (...) {
            std::cerr << Colors::RED << "Error: Cannot decrypt file, master password may be incorrect or file is corrupted"
                     << Colors::RESET << std::endl;
            exit(1);
        }

        return json;
    }

    void save_data(const SimpleJSON& json) {
        std::string json_str = json.toString();
        std::vector<unsigned char> plaintext(json_str.begin(), json_str.end());

        std::vector<unsigned char> iv(16);
        RAND_bytes(iv.data(), iv.size());
        auto encrypted_data = aes_encrypt(plaintext, master_key, iv);

        // Combine IV and ciphertext
        std::vector<unsigned char> encrypted;
        encrypted.insert(encrypted.end(), iv.begin(), iv.end());
        encrypted.insert(encrypted.end(), encrypted_data.begin(), encrypted_data.end());

        std::ofstream file(passwd_file, std::ios::binary);
        file.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
    }

public:
    PasswordManager() {
        // Get user home directory
#ifdef _WIN32
        const char* home = getenv("USERPROFILE");
#else
        const char* home = getenv("HOME");
#endif
        if (!home) {
            std::cerr << Colors::RED << "Error: Cannot get user home directory"
                     << Colors::RESET << std::endl;
            exit(1);
        }

        home_dir = fs::path(home);
        ssh_dir = home_dir / ".ssh";
        passwd_file = ssh_dir / "password.enc";

        // Check SSH key
        ssh_key_path = ssh_dir / "id_ed25519";
        if (!fs::exists(ssh_key_path)) {
            ssh_key_path = ssh_dir / "id_rsa";
        }
    }

    void add_password(const std::string& keyword, const std::string& username,
                     const std::string& password) {
        init_encryption();
        auto json = load_data();

        // Check if already exists
        for (auto& entry : json.data[keyword]) {
            if (entry.first == username) {
                std::cout << "Account '" << username << "' already exists under keyword '" << keyword
                         << "', overwrite? (y/n): ";
                std::string confirm;
                std::getline(std::cin, confirm);
                if (confirm != "y" && confirm != "Y") {
                    std::cout << Colors::YELLOW << "Operation cancelled" << Colors::RESET << std::endl;
                    return;
                }
                entry.second = password;
                save_data(json);
                std::cout << Colors::GREEN << "✓ Password updated: " << Colors::CYAN << keyword
                         << Colors::RESET << " - " << Colors::BLUE << username << Colors::RESET << std::endl;
                return;
            }
        }

        json.data[keyword].push_back({username, password});
        save_data(json);
        std::cout << Colors::GREEN << "✓ Password added: " << Colors::CYAN << keyword
                 << Colors::RESET << " - " << Colors::BLUE << username << Colors::RESET << std::endl;
    }

    void get_password(const std::string& keyword) {
        init_encryption();
        auto json = load_data();

        if (json.data.find(keyword) == json.data.end()) {
            std::cout << Colors::RED << "Keyword not found: " << keyword << Colors::RESET << std::endl;
            return;
        }

        const auto& entries = json.data[keyword];
        if (entries.empty()) {
            std::cout << Colors::YELLOW << "No password records under keyword '" << keyword << "'"
                     << Colors::RESET << std::endl;
            return;
        }

        std::cout << "\n" << Colors::BOLD << Colors::CYAN << "Keyword: " << keyword
                 << Colors::RESET << std::endl;
        std::cout << Colors::GRAY << std::string(60, '=') << Colors::RESET << std::endl;
        int i = 1;
        for (const auto& [username, password] : entries) {
            std::cout << Colors::YELLOW << i++ << "." << Colors::RESET
                     << " " << Colors::BOLD << "Account:" << Colors::RESET
                     << " " << Colors::BLUE << username << Colors::RESET << std::endl;
            std::cout << "   " << Colors::BOLD << "Password:" << Colors::RESET
                     << " " << Colors::GREEN << password << Colors::RESET << std::endl;
            std::cout << Colors::GRAY << std::string(60, '-') << Colors::RESET << std::endl;
        }
    }

    void update_password(const std::string& keyword, const std::string& username,
                        const std::string& new_password) {
        init_encryption();
        auto json = load_data();

        if (json.data.find(keyword) == json.data.end()) {
            std::cout << Colors::RED << "Keyword not found: " << keyword << Colors::RESET << std::endl;
            return;
        }

        bool found = false;
        for (auto& entry : json.data[keyword]) {
            if (entry.first == username) {
                entry.second = new_password;
                found = true;
                break;
            }
        }

        if (!found) {
            std::cout << Colors::RED << "Account not found: " << username << Colors::RESET << std::endl;
            return;
        }

        save_data(json);
        std::cout << Colors::GREEN << "✓ Password updated: " << Colors::CYAN << keyword
                 << Colors::RESET << " - " << Colors::BLUE << username << Colors::RESET << std::endl;
    }

    void delete_password(const std::string& keyword, const std::string& username = "") {
        init_encryption();
        auto json = load_data();

        if (json.data.find(keyword) == json.data.end()) {
            std::cout << Colors::RED << "Keyword not found: " << keyword << Colors::RESET << std::endl;
            return;
        }

        if (!username.empty()) {
            // Delete specific account
            auto& entries = json.data[keyword];
            auto original_size = entries.size();
            entries.erase(
                std::remove_if(entries.begin(), entries.end(),
                    [&username](const auto& entry) { return entry.first == username; }),
                entries.end()
            );

            if (entries.size() == original_size) {
                std::cout << Colors::RED << "Account not found: " << username << Colors::RESET << std::endl;
                return;
            }

            if (entries.empty()) {
                json.data.erase(keyword);
            }

            save_data(json);
            std::cout << Colors::GREEN << "✓ Password deleted: " << Colors::CYAN << keyword
                     << Colors::RESET << " - " << Colors::BLUE << username << Colors::RESET << std::endl;
        } else {
            // Delete entire keyword
            size_t count = json.data[keyword].size();
            std::cout << "Confirm deletion of all " << count << " accounts under keyword '" << keyword << "'? (y/n): ";
            std::string confirm;
            std::getline(std::cin, confirm);
            if (confirm != "y" && confirm != "Y") {
                std::cout << Colors::YELLOW << "Operation cancelled" << Colors::RESET << std::endl;
                return;
            }

            json.data.erase(keyword);
            save_data(json);
            std::cout << Colors::GREEN << "✓ Keyword deleted: " << Colors::CYAN << keyword
                     << Colors::RESET << " " << Colors::GRAY << "(" << count << " accounts)"
                     << Colors::RESET << std::endl;
        }
    }

    void list_keywords() {
        init_encryption();
        auto json = load_data();

        if (json.data.empty()) {
            std::cout << Colors::YELLOW << "Password vault is empty" << Colors::RESET << std::endl;
            return;
        }

        std::cout << "\n" << Colors::BOLD << Colors::CYAN << "All keywords:"
                 << Colors::RESET << std::endl;
        std::cout << Colors::GRAY << std::string(60, '=') << Colors::RESET << std::endl;
        for (const auto& [keyword, entries] : json.data) {
            std::cout << Colors::CYAN << "• " << Colors::RESET
                     << Colors::BOLD << keyword << Colors::RESET
                     << " " << Colors::GRAY << "(" << entries.size() << " accounts)"
                     << Colors::RESET << std::endl;
        }
        std::cout << Colors::GRAY << std::string(60, '=') << Colors::RESET << std::endl;
    }
};

void print_usage() {
    std::cout << R"(
)" << Colors::BOLD << Colors::CYAN << "Password Manager Usage:" << Colors::RESET << R"(

)" << Colors::BOLD << "1. Add password:" << Colors::RESET << R"(
   ./password add <keyword> <account> <password>

)" << Colors::BOLD << "2. Query password:" << Colors::RESET << R"(
   ./password get <keyword>
   ./password <keyword>

)" << Colors::BOLD << "3. Update password:" << Colors::RESET << R"(
   ./password update <keyword> <account> <new_password>

)" << Colors::BOLD << "4. Delete password:" << Colors::RESET << R"(
   ./password delete <keyword> [account]

)" << Colors::BOLD << "5. List all keywords:" << Colors::RESET << R"(
   ./password list

)" << Colors::YELLOW << "Note:" << Colors::RESET << R"( This tool supports two authentication methods:
  1. SSH key authentication (recommended): Auto-use ~/.ssh/id_ed25519 or ~/.ssh/id_rsa
  2. Manual password authentication: If no SSH key, enter master password each time
Password file stored at ~/.ssh/password.enc
)" << std::endl;
}

int main(int argc, char* argv[]) {
    // Set UTF-8 output (Windows)
#ifdef _WIN32
    system("chcp 65001 > nul");
#endif

    if (argc < 2) {
        print_usage();
        return 1;
    }

    PasswordManager manager;
    std::string command = argv[1];

    // Known commands
    std::vector<std::string> known_commands = {"add", "get", "update", "delete", "list"};
    bool is_known_command = std::find(known_commands.begin(), known_commands.end(), command) != known_commands.end();

    try {
        if (command == "add") {
            if (argc != 5) {
                std::cerr << Colors::RED << "Error: add command requires 3 arguments: <keyword> <account> <password>"
                         << Colors::RESET << std::endl;
                std::cerr << "Example: ./password add <keyword> <account> <password>" << std::endl;
                return 1;
            }
            manager.add_password(argv[2], argv[3], argv[4]);
        } else if (command == "get") {
            if (argc != 3) {
                std::cerr << Colors::RED << "Error: get command requires 1 argument: <keyword>"
                         << Colors::RESET << std::endl;
                std::cerr << "Example: ./password get <keyword>" << std::endl;
                return 1;
            }
            manager.get_password(argv[2]);
        } else if (command == "update") {
            if (argc != 5) {
                std::cerr << Colors::RED << "Error: update command requires 3 arguments: <keyword> <account> <new_password>"
                         << Colors::RESET << std::endl;
                std::cerr << "Example: ./password update <keyword> <account> <new_password>" << std::endl;
                return 1;
            }
            manager.update_password(argv[2], argv[3], argv[4]);
        } else if (command == "delete") {
            if (argc < 3 || argc > 4) {
                std::cerr << Colors::RED << "Error: delete command requires 1-2 arguments: <keyword> [account]"
                         << Colors::RESET << std::endl;
                std::cerr << "Example: ./password delete <keyword> <account>  # delete specific account" << std::endl;
                std::cerr << "Example: ./password delete <keyword>             # delete entire keyword" << std::endl;
                return 1;
            }
            manager.delete_password(argv[2], argc == 4 ? argv[3] : "");
        } else if (command == "list") {
            manager.list_keywords();
        } else if (!is_known_command) {
            // Treat as keyword for 'get' command
            manager.get_password(argv[1]);
        } else {
            std::cerr << Colors::RED << "Unknown command: " << command << Colors::RESET << std::endl;
            print_usage();
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "\n" << Colors::RED << "Error occurred: " << e.what() << Colors::RESET << std::endl;
        return 1;
    }

    return 0;
}
