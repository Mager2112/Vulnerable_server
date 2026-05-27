#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cctype>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>

#define PORT 8080
#define BUFFER_SIZE 4096

// Функция URL-декодирования
std::string urlDecode(const std::string& encoded) {
    std::string decoded;
    for (size_t i = 0; i < encoded.length(); ++i) {
        if (encoded[i] == '%' && i + 2 < encoded.length()) {
            std::string hex = encoded.substr(i + 1, 2);
            char ch = static_cast<char>(std::stoi(hex, nullptr, 16));
            decoded += ch;
            i += 2;
        } else if (encoded[i] == '+') {
            decoded += ' ';
        } else {
            decoded += encoded[i];
        }
    }
    return decoded;
}

struct User {
    int id;
    std::string name;
    std::string password;
};

struct Comment {
    std::string author;
    std::string text;
};

std::vector<User> users;
std::vector<Comment> comments;

void loadUsers() {
    std::ifstream file("data/users.txt");
    if (!file.is_open()) {
        users = {{1, "admin", "secret"}, {2, "alice", "alice123"}, {3, "bob", "bob123"}, {4, "eve", "eve123"}};
        return;
    }
    std::string line;
    while (std::getline(file, line)) {
        std::stringstream ss(line);
        User u;
        ss >> u.id >> u.name >> u.password;
        users.push_back(u);
    }
    file.close();
}

void loadComments() {
    std::ifstream file("data/comments.txt");
    if (!file.is_open()) {
        comments = {{"admin", "Hello world!"}, {"test", "This is a test comment"}};
        return;
    }
    std::string line;
    while (std::getline(file, line)) {
        size_t space = line.find(' ');
        if (space != std::string::npos) {
            Comment c;
            c.author = line.substr(0, space);
            c.text = line.substr(space + 1);
            comments.push_back(c);
        }
    }
    file.close();
}

// 🚨 УЯЗВИМОСТЬ 1: SQL-инъекция (эмуляция)
std::string searchUsers(const std::string& search_term) {
    std::string decoded = urlDecode(search_term);
    std::string result = "<h3>Search results for: " + decoded + "</h3><ul>";
    
    // Проверка на инъекцию - ищем опасные паттерны
    bool is_injection = (decoded.find("OR 1=1") != std::string::npos ||
                         decoded.find("' OR '1'='1") != std::string::npos ||
                         decoded.find("\" OR \"1\"=\"1") != std::string::npos ||
                         decoded.find("1=1") != std::string::npos);
    
    if (is_injection) {
        result += "<li style='color:red'><b>[SQL INJECTION DETECTED] Returning ALL users:</b></li>";
        for (const auto& u : users) {
            result += "<li>User: " + u.name + " (id:" + std::to_string(u.id) + ")</li>";
        }
    } else {
        for (const auto& u : users) {
            if (u.name.find(decoded) != std::string::npos || decoded.empty()) {
                result += "<li>User: " + u.name + " (id:" + std::to_string(u.id) + ")</li>";
            }
        }
        if (!decoded.empty() && result.find("<li>User:") == std::string::npos) {
            result += "<li>No users found</li>";
        }
    }
    result += "</ul>";
    return result;
}

// 🚨 УЯЗВИМОСТЬ 2: XSS — комментарии выводятся БЕЗ ЭКРАНИРОВАНИЯ
std::string renderComments() {
    std::string result = "<h3>Comments:</h3><div class='comments'>";
    for (const auto& c : comments) {
        // 🔴 ОПАСНО: пользовательский текст вставляется напрямую
        result += "<div class='comment'><b>" + c.author + ":</b> " + c.text + "</div>";
    }
    result += "</div>";
    return result;
}

// Добавление комментария с сохранением в файл
void addComment(const std::string& author, const std::string& text) {
    Comment c;
    c.author = urlDecode(author);
    c.text = urlDecode(text);
    comments.push_back(c);
    
    std::ofstream file("data/comments.txt", std::ios::app);
    file << c.author << " " << c.text << "\n";
    file.close();
}

// 🚨 УЯЗВИМОСТЬ 3: Path Traversal
std::string readFile(const std::string& filename) {
    std::string decoded = urlDecode(filename);
    std::string path = "data/" + decoded;
    
    // Проверка на попытку выйти из папки data
    if (decoded.find("..") != std::string::npos) {
        // Пытаемся прочитать любой файл (уязвимость!)
        std::ifstream file(decoded);
        if (file.is_open()) {
            std::stringstream buffer;
            buffer << file.rdbuf();
            file.close();
            return "<pre style='color:red'>[PATH TRAVERSAL] Read file: " + decoded + "\n\n" + buffer.str() + "</pre>";
        }
        return "<p style='color:red'>[PATH TRAVERSAL ATTEMPT] Cannot read: " + decoded + "</p>";
    }
    
    std::ifstream file(path);
    if (!file.is_open()) {
        return "<p>File not found: " + decoded + "</p>";
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();
    return "<pre>" + buffer.str() + "</pre>";
}

std::string httpResponse(const std::string& body) {
    return "HTTP/1.1 200 OK\r\n"
           "Content-Type: text/html; charset=utf-8\r\n"
           "Content-Length: " + std::to_string(body.size()) + "\r\n"
           "Connection: close\r\n\r\n" + body;
}

void handleRequest(const std::string& request, std::string& response) {
    std::string html_template = R"(
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Test Server - C++</title>
    <style>
        body { font-family: monospace; margin: 40px; background: #1e1e1e; color: #d4d4d4; }
        .container { max-width: 900px; margin: auto; }
        .vuln { border: 2px solid #ff5555; padding: 20px; margin: 20px 0; background: #2d2d2d; border-radius: 10px; }
        .warning { color: #ff5555; font-weight: bold; }
        input, textarea { width: 100%; padding: 8px; margin: 5px 0; background: #3c3c3c; border: 1px solid #555; color: #fff; }
        button { padding: 10px 20px; background: #007acc; color: white; border: none; cursor: pointer; border-radius: 5px; }
        button:hover { background: #005a9e; }
        .comment { border-bottom: 1px solid #555; padding: 10px; }
        h1, h2, h3 { color: #fff; }
        pre { background: #000; padding: 10px; overflow-x: auto; }
    </style>
</head>
<body>
<div class='container'>
    <h1>🔴 Vulnerable Test Server (C++)</h1>
    <p class='warning'>⚠️ This server contains REAL VULNERABILITIES for testing static analyzers!</p>
    
    <div class='vuln'>
        <h2>1. Search Users (SQL Injection emulation)</h2>
        <form method='GET' action='/search'>
            <input type='text' name='q' placeholder='Try: OR 1=1  or  admin'  value=''/>
            <button type='submit'>Search</button>
        </form>
        %SEARCH_RESULTS%
    </div>
    
    <div class='vuln'>
        <h2>2. Comments (XSS vulnerability)</h2>
        <form method='GET' action='/add_comment'>
            <input type='text' name='author' placeholder='Your name'/>
            <textarea name='text' rows='3' placeholder='Try: &lt;script&gt;alert("XSS")&lt;/script&gt;'></textarea>
            <button type='submit'>Add Comment</button>
        </form>
        %COMMENTS%
    </div>
    
    <div class='vuln'>
        <h2>3. File Download (Path Traversal)</h2>
        <form method='GET' action='/file'>
            <input type='text' name='name' placeholder='Try: ../../../etc/passwd'/>
            <button type='submit'>Read File</button>
        </form>
        %FILE_CONTENT%
    </div>
</div>
</body>
</html>
)";
    
    std::string method, path, version;
    std::istringstream req_stream(request);
    req_stream >> method >> path >> version;
    
    std::string search_results, comments_html, file_content;
    comments_html = renderComments();
    
    // Обработка /search?q=...
    if (path.find("/search") == 0) {
        size_t q_pos = path.find("q=");
        if (q_pos != std::string::npos) {
            size_t end = path.find("&", q_pos);
            std::string query = path.substr(q_pos + 2, end - q_pos - 2);
            search_results = searchUsers(query);
        } else {
            search_results = "<p>No search query provided</p>";
        }
    }
    
    // Обработка /add_comment?author=&text=...
    if (path.find("/add_comment") == 0) {
        size_t author_pos = path.find("author=");
        size_t text_pos = path.find("text=");
        if (author_pos != std::string::npos && text_pos != std::string::npos) {
            size_t author_end = path.find("&", author_pos);
            std::string author = path.substr(author_pos + 7, author_end - author_pos - 7);
            std::string text = path.substr(text_pos + 5);
            addComment(author, text);
            comments_html = renderComments();
        }
    }
    
    // Обработка /file?name=...
    if (path.find("/file") == 0) {
        size_t name_pos = path.find("name=");
        if (name_pos != std::string::npos) {
            size_t end = path.find("&", name_pos);
            std::string filename = path.substr(name_pos + 5, end - name_pos - 5);
            file_content = readFile(filename);
        }
    }
    
    std::string final_html = html_template;
    
    size_t pos;
    pos = final_html.find("%SEARCH_RESULTS%");
    if (pos != std::string::npos) final_html.replace(pos, 17, search_results);
    
    pos = final_html.find("%COMMENTS%");
    if (pos != std::string::npos) final_html.replace(pos, 10, comments_html);
    
    pos = final_html.find("%FILE_CONTENT%");
    if (pos != std::string::npos) final_html.replace(pos, 16, file_content);
    
    response = httpResponse(final_html);
}

int main() {
    loadUsers();
    loadComments();
    
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    bind(server_fd, (struct sockaddr*)&address, sizeof(address));
    listen(server_fd, 3);
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "🔥 Vulnerable server running!" << std::endl;
    std::cout << "   URL: http://localhost:" << PORT << std::endl;
    std::cout << "\n📌 TEST THESE ATTACKS:" << std::endl;
    std::cout << "   1. SQLi:  http://localhost:8080/search?q=OR 1=1" << std::endl;
    std::cout << "   2. XSS:   Add comment with: <script>alert('XSS')</script>" << std::endl;
    std::cout << "   3. Path:  http://localhost:8080/file?name=../../../etc/passwd" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    while (true) {
        new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        read(new_socket, buffer, BUFFER_SIZE);
        
        std::string response;
        handleRequest(buffer, response);
        
        send(new_socket, response.c_str(), response.size(), 0);
        close(new_socket);
        
        memset(buffer, 0, BUFFER_SIZE);
    }
    
    return 0;
}