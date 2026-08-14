// Source reconstruction of the supplied anime_player ELF executable

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <new>
#include <vector>

class Media {
public:
    int media_type;
    char media_name[32];

    Media(int type, const char* name) : media_type(type) {
        std::strncpy(media_name, name, sizeof(media_name) - 1);
        media_name[sizeof(media_name) - 1] = '\0';
    }

    virtual void show_info() {
        std::cout << "Media: " << media_name << " (Type: " << media_type << ")\n";
    }

    virtual void play() {
        std::cout << "Playing: " << media_name << '\n';
    }

    virtual ~Media() = default;
};

class AnimeStream : public Media {
public:
    char title[32];
    char episode[16];
    char stream_url[64];

    AnimeStream(const char* anime_title, const char* anime_episode, const char* url)
        : Media(1, anime_title) {
        std::strncpy(title, anime_title, sizeof(title) - 1);
        std::strncpy(episode, anime_episode, sizeof(episode) - 1);
        std::strncpy(stream_url, url, sizeof(stream_url) - 1);
    }

    void show_info() override {
        std::cout << "\n--- Anime Info ---\n";
        std::cout << "Title: " << title << '\n';
        std::cout << "Episode: " << episode << '\n';
        std::cout << "Stream: " << stream_url << '\n';
    }

    void play() override {
        std::cout << "\nStreaming: " << title << " - Ep " << episode << '\n';
        std::cout << "Connecting to " << stream_url << "...\n";
    }

    virtual void execute_stream() {
        std::cout << "[+] Stream engine launching media processor for: " << stream_url << '\n';
        std::system(stream_url);
    }
};

static_assert(sizeof(Media) == 48, "This reconstruction expects the x86-64 GCC ABI");
static_assert(sizeof(AnimeStream) == 160, "This reconstruction expects the x86-64 GCC ABI");

std::vector<void*> inventory;

void setup_io() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stdin, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
}

void banner() {
    std::puts("===================================");
    std::puts("      AnimeFlix Player v2.0        ");
    std::puts("===================================");
}

void menu() {
    std::puts("\n1. Add Anime Stream");
    std::puts("2. Add Raw Stream Config");
    std::puts("3. View Media Details");
    std::puts("4. Play Media Stream");
    std::puts("5. Delete Media Item");
    std::puts("6. Update Anime Stream URL");
    std::puts("7. Export Media Header");
    std::puts("8. Exit");
    std::printf("Choice > ");
}

void view_media() {
    std::size_t index;
    std::cout << "Index: ";
    std::cin >> std::dec >> index;

    if (index < inventory.size() && inventory[index] != nullptr) {
        static_cast<Media*>(inventory[index])->show_info();
    }
}

void play_media() {
    std::size_t index;
    std::cout << "Index: ";
    std::cin >> std::dec >> index;

    if (index < inventory.size() && inventory[index] != nullptr) {
        static_cast<Media*>(inventory[index])->play();
    }
}

void delete_media() {
    std::size_t index;
    std::cout << "Index: ";
    std::cin >> std::dec >> index;

    if (index < inventory.size() && inventory[index] != nullptr) {
        // The original leaves the freed pointer in inventory.
        delete static_cast<Media*>(inventory[index]);
        std::cout << "[+] Deleted item at index " << index << '\n';
    }
}

void update_anime_url() {
    std::size_t index;
    std::cout << "Index: ";
    std::cin >> std::dec >> index;

    if (index < inventory.size() && inventory[index] != nullptr) {
        // The original performs this unchecked cast even for raw entries.
        auto* anime = static_cast<AnimeStream*>(inventory[index]);
        std::cout << "New URL: ";
        std::cin >> std::ws;
        std::cin.getline(anime->stream_url, sizeof(anime->stream_url));
    }
}

void export_media() {
    std::size_t index;
    std::cout << "Index: ";
    std::cin >> std::dec >> index;

    if (index < inventory.size() && inventory[index] != nullptr) {
        std::cout << "Object Address: " << inventory[index] << '\n';
        std::cout << "Vtable Pointer: " << *static_cast<void**>(inventory[index]) << '\n';
    }
}

void add_anime() {
    char title[32];
    char episode[16];
    char url[64];

    std::cout << "Title: ";
    std::cin >> std::ws;
    std::cin.getline(title, sizeof(title));

    std::cout << "Episode: ";
    std::cin.getline(episode, sizeof(episode));

    std::cout << "URL: ";
    std::cin.getline(url, sizeof(url));

    auto* anime = new AnimeStream(title, episode, url);
    inventory.push_back(anime);
    std::cout << "[+] Added at index " << inventory.size() - 1 << '\n';
}

void add_raw_config() {
    std::uintptr_t target_vtable;
    std::uintptr_t slots[14]{};

    std::cout << "Target Vtable Ptr (hex): 0x";
    std::cin >> std::hex >> target_vtable;

    std::cout << "Slot 0 (hex): 0x";
    std::cin >> std::hex >> slots[0];

    std::cout << "Slot 1 (hex): 0x";
    std::cin >> std::hex >> slots[1];

    constexpr std::size_t raw_size = sizeof(target_vtable) + sizeof(slots);
    static_assert(raw_size == 120);

    void* raw = ::operator new(raw_size);
    *static_cast<std::uintptr_t*>(raw) = target_vtable;
    std::memcpy(static_cast<char*>(raw) + sizeof(target_vtable), slots,
                sizeof(slots));

    inventory.push_back(raw);
    std::cout << "[+] Added at index " << inventory.size() - 1 << '\n';
}

int main() {
    setup_io();
    banner();

    while (true) {
        menu();

        int choice;
        if (!(std::cin >> std::dec >> choice)) {
            return 0;
        }

        switch (choice) {
        case 1:
            add_anime();
            break;
        case 2:
            add_raw_config();
            break;
        case 3:
            view_media();
            break;
        case 4:
            play_media();
            break;
        case 5:
            delete_media();
            break;
        case 6:
            update_anime_url();
            break;
        case 7:
            export_media();
            break;
        case 8:
            return 0;
        default:
            std::puts("Invalid choice");
            break;
        }
    }
}
