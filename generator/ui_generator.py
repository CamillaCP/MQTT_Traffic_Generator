import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import pandas as pd
import subprocess
import signal
import os

# Global variable to track the generator process ('generator.py' script)
generator_process = None

# Function to save configurations to a CSV file
def save_to_csv():
    # Check if there are any configurations to save
    if not configs:
        # Show error if no configurations are found
        messagebox.showerror("Error", "No configurations to save!")
        return

    # Open a save dialog to let the user specify the file name and location for the CSV
    save_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                             filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
    if save_path:
        # Convert the configurations list into a DataFrame to save it as a CSV file
        df = pd.DataFrame(configs)
        df.to_csv(save_path, index=False)
        messagebox.showinfo("Success", f"Configurations saved to {save_path}")
        # Update the global CSV file path variable
        global csv_file_path
        csv_file_path = save_path

# Function to handle PCAP file selection for the Empirical Distribution Mode
def select_pcap_file():
    # Open file dialog to let the user select the PCAP file to replay
    pcap_file = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
    if pcap_file:
        # Confirm file selection
        messagebox.showinfo("File Selected", f"Selected PCAP file: {pcap_file}")
        # Update the global PCAP file path variable
        global pcap_file_path
        pcap_file_path = pcap_file

# Function to start the generator process
def run_generator():
    global generator_process
    # Check if the CSV file path is set and if it exists
    if csv_file_path and os.path.exists(csv_file_path):
        try:
            # Start the generator process using the CSV file as input
            generator_process = subprocess.Popen(['python3', 'generator.py', '--csv', csv_file_path],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
            messagebox.showinfo("Info", f"Generator started with CSV: {csv_file_path}")
            # Enable the Stop button, that is otherwise disabled if no generation process has started
            toggle_stop_button(True)
        # Error handling
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start generator: {e}")
    # Check if the PCAP file path is set and if it exists
    elif pcap_file_path and os.path.exists(pcap_file_path):
        try:
            # Start the generator process using the CSV file as input
            generator_process = subprocess.Popen(['python3', 'generator.py', '--pcap', pcap_file_path],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
            messagebox.showinfo("Info", f"Generator started with PCAP: {pcap_file_path}")
            # Enable the Stop button, that is otherwise disabled if no generation process has started
            toggle_stop_button(True)
        # Error handling
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start generator: {e}")
    else:
        messagebox.showerror("Error", "Please select a valid CSV or PCAP file before running the generator.")

# Function to validate user inputs
def validate_inputs():
    try:
        # Check all the required fields and show error if any are empty or invalid
        if not role_var.get().strip():
            raise ValueError("Role cannot be empty.")
        if not topic_var.get().strip():
            raise ValueError("Topic cannot be empty.")
        qos = qos_var.get()
        # Ensure QoS is within acceptable range
        if qos not in [0, 1, 2]:
            raise ValueError("QoS must be 0, 1, or 2.")
        if role_var.get().lower() == "publisher":
            if not type_var.get().strip():
                raise ValueError("Type cannot be empty for publishers.")
            if not payload_var.get().strip():
                raise ValueError("Payload cannot be empty.")
            if type_var.get().lower() == "periodic":
                period = period_var.get()
                if period <= 0:
                    raise ValueError("Period must be a positive number.")
            if type_var.get().lower() == "event":
                min_range = min_range_var.get()
                max_range = max_range_var.get()
                # Ensure maximum time range is greater than the minimum one
                if min_range >= max_range:
                    raise ValueError("MinRange must be less than MaxRange.")
            if not device_type_var.get().strip():
                raise ValueError("DeviceType cannot be empty.")
            if device_type_var.get().lower() == "counterfeit" and not hidden_message_var.get().strip():
                raise ValueError("Hidden Message cannot be empty when DeviceType is counterfeit.")
        if role_var.get().lower() == "dos_attack":
            if num_clients_var.get() <= 0:
                raise ValueError("NumClients must be a positive number.")
            if duration_var.get() <= 0:
                raise ValueError("Duration must be a positive number.")
        # Return True if all the validations are passed
        return True
    # Show error message if any validation fails
    except ValueError as ve:
        messagebox.showerror("Input Error", str(ve))
        return False

# Function to add a new configuration entry to the list
def add_config():
    selected_type = (
        type_var.get().lower() if role_var.get().lower() == 'publisher'
        else "periodic" if role_var.get().lower() == 'dos_attack'
        else None
    )
    # Validate inputs before proceeding
    if validate_inputs():
        # Create a dictionary with the configuration values, converting key names to lowercase
        config = {
            "Topic": topic_var.get(),
            "Type": selected_type,
            "QoS": qos_var.get(),
            "Period": period_var.get() if type_var.get().lower() == 'periodic' else None,
            "MinRange": min_range_var.get() if type_var.get().lower() == 'event' else None,
            "MaxRange": max_range_var.get() if type_var.get().lower() == 'event' else None,
            "Payload": payload_var.get(),
            "Distribution": distribution_var.get().lower() if type_var.get().lower() == 'event' else None,
            "DeviceType": "counterfeit" if role_var.get().lower() == 'dos_attack' else device_type_var.get().lower(),
            "HiddenMessage": None if role_var.get().lower() == 'dos_attack' else hidden_message_var.get(),
            "EmbeddingMethod": embedding_method_var.get().lower() if device_type_var.get().lower() == 'counterfeit' else None,
            "Role": role_var.get().lower(),
            "NumClients": num_clients_var.get() if role_var.get().lower() == 'dos_attack' else None,
            "Duration": duration_var.get() if role_var.get().lower() == 'dos_attack' else None
        }
        # Add the configuration to the configurations list
        configs.append(config)
        messagebox.showinfo("Info", "Configuration added successfully")
        # Clear fields after the configuration is added
        clear_fields()

# Function to stop the running generator process
def stop_generator():
    global generator_process
    if generator_process:
        try:
            # Send a termination signal to the generator process
            os.killpg(os.getpgid(generator_process.pid), signal.SIGTERM)
            # Reset the generator process variable
            generator_process = None
            # Disable the Stop button
            toggle_stop_button(False)
            messagebox.showinfo("Info", "Generator stopped successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to stop generator: {e}")
    else:
        messagebox.showerror("Error", "No generator is currently running.")

# Function to toggle the visibility of the stop button
def toggle_stop_button(visible):
    if visible:
        # Show Stop button
        stop_button.pack(side=tk.RIGHT, padx=20, pady=10)
    else:
        # Hide Stop button
        stop_button.pack_forget()

# Function to clear the input fields and reset the UI
def clear_fields():
    role_var.set("")
    topic_var.set("")
    type_var.set("")
    qos_var.set("")
    payload_var.set("")
    period_var.set(0)
    min_range_var.set(0)
    max_range_var.set(0)
    distribution_var.set("")
    device_type_var.set("")
    hidden_message_var.set("")
    # Refresh the UI to hide/show fields based on selections
    show_hide_fields()

# Function to control the visibility of the input fields based on user selections
def show_hide_fields():
    # Hide all fields by default
    for widget in main_frame.winfo_children():
        widget.grid_remove()

    mode_frame.grid(row=0, column=0, columnspan=2, pady=15, sticky='ew')

    # If Manual Configuration is selected, show the relevant fields
    if mode_var.get() == "Manual Configuration":
        role_frame.grid(row=1, column=0, columnspan=2, pady=10, sticky='ew')

        if role_var.get():
            topic_frame.grid(row=2, column=0, pady=10, padx=(0, 5), sticky='ew')
            qos_frame.grid(row=2, column=1, pady=10, padx=(5, 0), sticky='ew')

            # If Publisher role, show Publisher-specific fields
            if role_var.get().lower() == "publisher":
                type_frame.grid(row=3, column=0, pady=10, padx=(0, 5), sticky='ew')
                payload_frame.grid(row=3, column=1, pady=10, padx=(5, 0), sticky='ew')

                if type_var.get().lower() == "periodic":
                    period_frame.grid(row=4, column=0, columnspan=2, pady=10, sticky='ew')
                elif type_var.get().lower() == "event":
                    min_range_frame.grid(row=4, column=0, pady=10, padx=(0, 5), sticky='ew')
                    max_range_frame.grid(row=4, column=1, pady=10, padx=(5, 0), sticky='ew')
                    distribution_frame.grid(row=5, column=0, columnspan=2, pady=10, sticky='ew')

                device_type_frame.grid(row=6, column=0, columnspan=2, pady=10, sticky='ew')
                if device_type_var.get().lower() == "counterfeit":
                    hidden_message_frame.grid(row=7, column=0, columnspan=2, pady=10, sticky='ew')
                    embedding_method_frame.grid(row=8, column=0, columnspan=2, pady=10, sticky='ew')

            # If DoS Attack role, show DoS-specific fields
            elif role_var.get().lower() == "dos_attack":
                device_type_var.set("counterfeit")
                type_var.set("periodic")
                type_frame.grid(row=3, column=0, pady=10, padx=(0, 5), sticky='ew')
                type_frame.winfo_children()[1].configure(state="disabled")  # Make the dropdown non-editable

                # Show DoS-specific fields: Payload, Period, NumClients, Duration
                payload_frame.grid(row=4, column=0, columnspan=2, pady=10, sticky='ew')
                period_frame.grid(row=5, column=0, columnspan=2, pady=10, sticky='ew')
                num_clients_frame.grid(row=6, column=0, pady=10, padx=(0, 5), sticky='ew')
                duration_frame.grid(row=6, column=1, pady=10, padx=(5, 0), sticky='ew')

                # Hide unnecessary fields for DoS Attack
                hidden_message_var.set("")  # Clear HiddenMessage if previously set
                hidden_message_frame.grid_forget()
                embedding_method_frame.grid_forget()
                device_type_frame.grid_forget()  # Hide DeviceType

    # If Empirical Distribution Mode is selected only show the PCAP file selection
    elif mode_var.get() == "Empirical Distribution Mode":
        pcap_button.grid(row=1, column=0, columnspan=2, padx=10, pady=20, sticky='ew')

# Global variables for CSV and PCAP file paths
csv_file_path = None
pcap_file_path = None

# Initialize the main window for the UI
root = tk.Tk()
root.title("MQTT Traffic Generator Configuration")
root.geometry("630x950")
root.configure(bg="#ddd5f3")

# Define background color
bg_color = "#cec2eb"
root.configure(bg=bg_color)

# Configure styling for widgets
style = ttk.Style()
style.theme_use('clam')
style.configure('TFrame', background=bg_color)
style.configure('TLabel', background=bg_color, font=("Helvetica", 12))
style.map('TCombobox', fieldbackground=[('readonly', '#ddd5f3')])
style.map('TEntry', fieldbackground=[('!disabled', '#ddd5f3')])
style.configure('TButton', font=("Helvetica", 11))

# Define Tkinter variables for each input field
mode_var = tk.StringVar()
role_var = tk.StringVar()
topic_var = tk.StringVar()
type_var = tk.StringVar(value="")
qos_var = tk.IntVar()
payload_var = tk.StringVar()
period_var = tk.DoubleVar()
min_range_var = tk.DoubleVar()
max_range_var = tk.DoubleVar()
distribution_var = tk.StringVar()
device_type_var = tk.StringVar(value="")
hidden_message_var = tk.StringVar()
embedding_method_var = tk.StringVar()
num_clients_var = tk.IntVar(value=1)
duration_var = tk.DoubleVar(value=10)

# List to hold the configuration entries before saving to CSV
configs = []

# Title Label
title_label = ttk.Label(root, text="MQTT Traffic Generator", font=("Helvetica", 24, "bold"), style='TLabel')
title_label.pack(pady=30)

# Create main frame to hold the input fields
main_frame = ttk.Frame(root, padding="20", style='TFrame')
main_frame.pack(padx=40, pady=20, fill="both", expand=True)
main_frame.columnconfigure(0, weight=1)
main_frame.columnconfigure(1, weight=1)

# Helper functions to create a labeled combobox and entry widgets
def create_labeled_combobox(parent, label_text, variable, values):
    frame = ttk.Frame(parent)
    label = ttk.Label(frame, text=label_text)
    label.pack(side="top", pady=(0, 5))
    combobox = ttk.Combobox(frame, textvariable=variable, values=values, state="readonly")
    combobox.pack(side="top", fill="x")
    return frame

def create_labeled_entry(parent, label_text, variable):
    frame = ttk.Frame(parent)
    label = ttk.Label(frame, text=label_text)
    label.pack(side="top", pady=(0, 5))
    entry = ttk.Entry(frame, textvariable=variable)
    entry.pack(side="top", fill="x")
    return frame

# Create labeled combobox and entry fields for each section
mode_frame = create_labeled_combobox(main_frame, "Mode", mode_var, ["Manual Configuration", "Empirical Distribution Mode"])
role_frame = create_labeled_combobox(main_frame, "Role", role_var, ["Publisher", "Subscriber", "DoS_Attack"])
topic_frame = create_labeled_entry(main_frame, "Topic", topic_var)
qos_frame = create_labeled_combobox(main_frame, "Quality of Service", qos_var, [0, 1, 2])
type_frame = create_labeled_combobox(main_frame, "Device Timing", type_var, ["Periodic", "Event"])
payload_frame = create_labeled_entry(main_frame, "Payload", payload_var)
period_frame = create_labeled_entry(main_frame, "Period", period_var)
min_range_frame = create_labeled_entry(main_frame, "Minimum Time Range", min_range_var)
max_range_frame = create_labeled_entry(main_frame, "Maximum Time Range", max_range_var)
distribution_frame = create_labeled_combobox(main_frame, "Distribution", distribution_var, ["Uniform", "Exponential", "Normal"])
device_type_frame = create_labeled_combobox(main_frame, "Device Type", device_type_var, ["Legit", "Counterfeit"])
hidden_message_frame = create_labeled_entry(main_frame, "Hidden Message", hidden_message_var)
embedding_method_frame = create_labeled_combobox(main_frame, "Embedding Method", embedding_method_var, ["Case", "ID"])
num_clients_frame = create_labeled_entry(main_frame, "NumClients", num_clients_var)
duration_frame = create_labeled_entry(main_frame, "Duration", duration_var)
# Button to select PCAP file
pcap_button = ttk.Button(main_frame, text="Select PCAP File", command=select_pcap_file)

# Button frame for configuration control buttons
button_frame = ttk.Frame(root)
button_frame.pack(pady=20, fill="x")

add_button = ttk.Button(button_frame, text="Add Configuration", command=add_config)
add_button.pack(side=tk.LEFT, padx=20, pady=10)

save_button = ttk.Button(button_frame, text="Save to CSV", command=save_to_csv)
save_button.pack(side=tk.LEFT, padx=20, pady=10)

run_button = ttk.Button(button_frame, text="Run Generator", command=run_generator)
run_button.pack(side=tk.LEFT, padx=20, pady=10)

stop_button = ttk.Button(button_frame, text="Stop Generator", command=stop_generator)
toggle_stop_button(False)

# Bind events to update field visibility when certain selections change
mode_var.trace('w', lambda *args: show_hide_fields())
role_var.trace('w', lambda *args: show_hide_fields())
type_var.trace('w', lambda *args: show_hide_fields())
device_type_var.trace('w', lambda *args: show_hide_fields())

# Show/hide fields based on initial mode selection
show_hide_fields()

# Run the UI event loop
root.mainloop()
