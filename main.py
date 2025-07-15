import random
import threading
import time
from tkinter import *
from tkinter import messagebox, simpledialog
from collections import deque

# Tkinter root setup
root = Tk()
root.geometry("800x580")
root.title("OS Project")
root.config(bg="#1E1E2F")


def clear_frame():
    for widget in root.winfo_children():
        if widget.winfo_class() != "Menu":
            widget.destroy()



def styled_button1(root, text, command):
    btn = Button(root, text=text, bg="#FF5733", fg="white", height=2, width=22, font=("Arial", 12, "bold"),
                 relief=RAISED, bd=5, command=command, cursor="hand2")
    btn.bind("<Enter>", lambda e: btn.config(bg="#C70039"))
    btn.bind("<Leave>", lambda e: btn.config(bg="#FF5733"))
    btn.pack(side=LEFT, padx=20, pady=15)
    return btn


def styled_button2(root, text, command):
    btn = Button(root, text=text, bg="#1ABC9C", fg="White", height=2, width=18, font=("Arial", 12, "bold"),
                 relief=RAISED, bd=5, command=command, cursor="hand2")
    btn.bind("<Enter>", lambda e: btn.config(bg="aquamarine"))
    btn.bind("<Leave>", lambda e: btn.config(bg="#1ABC9C"))
    btn.pack(side=LEFT, padx=20, pady=15)
    return btn


ready_queue = deque()
blocked_queue = deque()
suspended_queue = deque()
running_process = None
used_pids = set()
process_messages = {}
system_config = {
    "max_processes": 900,
    "scheduling_algo": "Priority-based"
}

READY = "Ready"
RUNNING = "Running"
BLOCKED = "Blocked"
SUSPENDED = "Suspended"

IO_IDLE = "IDLE"
IO_WAITING = "WAITING"


def process_management():
    clear_frame()
    global ready_queue, blocked_queue, suspended_queue, running_process, used_pids

    def back():
        clear_frame()
        main2()

    def create_process(name, priority, owner="User", memory_req=100, arrival_time=0, burst_time=1):
        global used_pids, process_messages
        if len(used_pids) >= system_config["max_processes"]:
            return "Maximum number of processes reached."

        while True:
            pid = random.randint(100, 999)
            if pid not in used_pids:
                used_pids.add(pid)
                break

        process = {
            "pid": pid,
            "name": name,
            "priority": priority,
            "state": READY,
            "owner": owner,
            "memory_req": memory_req,
            "memory_addr": f"0x{random.randint(1000, 9999):04X}",
            "registers": {"AX": 0, "BX": 0, "CX": 0, "DX": 0},
            "processor": 0,
            "io_state": IO_IDLE,
            "arrival_time": arrival_time,
            "burst_time": burst_time,
            "devices": []
        }
        ready_queue.append(process)
        process_messages[pid] = []
        return f"Created: PID={pid}, Name={name}, Priority={priority}, Owner={owner}"

    def find_process_by_pid(pid):
        global running_process
        for queue in [ready_queue, blocked_queue, suspended_queue]:
            for p in queue:
                if p["pid"] == pid:
                    return p
        if running_process and running_process["pid"] == pid:
            return running_process
        return None

    def process_communication_dialog():
        pid_sender = simpledialog.askinteger("Send Message", "Enter sender PID:", parent=root, minvalue=100,
                                             maxvalue=999)
        if pid_sender is None:
            return
        sender = find_process_by_pid(pid_sender)
        if not sender:
            messagebox.showerror("Error", "Sender PID not found.")
            return

        pid_receiver = simpledialog.askinteger("Send Message", "Enter receiver PID:", parent=root, minvalue=100,
                                               maxvalue=999)
        if pid_receiver is None:
            return
        receiver = find_process_by_pid(pid_receiver)
        if not receiver:
            messagebox.showerror("Error", "Receiver PID not found.")
            return

        msg = simpledialog.askstring("Send Message", "Enter message content:", parent=root)
        if not msg:
            messagebox.showerror("Error", "Empty message.")
            return

        process_messages[pid_receiver].append((pid_sender, msg))
        messagebox.showinfo("Success", f"Message sent from PID {pid_sender} to PID {pid_receiver}.")

    def destroy_process(pid):
        global running_process
        for queue in [ready_queue, blocked_queue, suspended_queue]:
            for process in list(queue):
                if process["pid"] == pid:
                    queue.remove(process)
                    used_pids.discard(pid)
                    return f"Destroyed process {pid}"
        if running_process and running_process["pid"] == pid:
            used_pids.discard(pid)
            running_process = None
            return f"Destroyed running process {pid}"
        return "Process not found."

    def suspend_process(pid):
        global running_process
        for queue in [ready_queue, blocked_queue]:
            for process in list(queue):
                if process["pid"] == pid:
                    queue.remove(process)
                    process["state"] = SUSPENDED
                    suspended_queue.append(process)
                    return f"Suspended process {pid}"
        if running_process and running_process["pid"] == pid:
            running_process["state"] = SUSPENDED
            suspended_queue.append(running_process)
            running_process = None
            return f"Suspended running process {pid}"
        return "Process not found or already suspended."

    def resume_process(pid):
        for process in list(suspended_queue):
            if process["pid"] == pid:
                suspended_queue.remove(process)
                process["state"] = READY
                ready_queue.append(process)
                return f"Resumed process {pid}"
        return "Suspended process not found."

    def block_process(pid):
        global running_process
        if running_process and running_process["pid"] == pid:
            running_process["state"] = BLOCKED
            blocked_queue.append(running_process)
            running_process = None
            return f"Blocked running process {pid}"
        return "Error: Only a running process can be blocked."

    def wakeup_process(pid):
        for process in list(blocked_queue):
            if process["pid"] == pid:
                blocked_queue.remove(process)
                process["state"] = READY
                ready_queue.append(process)
                return f"Woke up process {pid}"
        return "Blocked process not found."

    def dispatch_process():
        global running_process
        if running_process:
            running_process["state"] = READY
            ready_queue.append(running_process)

        if not ready_queue:
            running_process = None
            return "No process to dispatch."

        sorted_queue = sorted(ready_queue, key=lambda p: p["priority"])
        running_process = sorted_queue.pop(0)
        ready_queue.clear()
        ready_queue.extend(sorted_queue)
        running_process["state"] = RUNNING
        return f"Dispatched process {running_process['pid']}"

    def change_priority(pid, new_priority):
        for queue in [ready_queue, blocked_queue, suspended_queue]:
            for process in queue:
                if process["pid"] == pid:
                    process["priority"] = new_priority
                    return f"Priority changed for process {pid}"
        if running_process and running_process["pid"] == pid:
            running_process["priority"] = new_priority
            return f"Priority changed for running process {pid}"
        return "Process not found."

    def view_messages_dialog():
        pid = simpledialog.askinteger("View Messages", "Enter PID to view messages:", parent=root, minvalue=100,
                                      maxvalue=999)
        if pid is None:
            return
        if pid not in process_messages or not process_messages[pid]:
            messagebox.showinfo("Messages", f"No messages for PID {pid}.")
            return

        msgs = process_messages[pid]
        text = "\n".join([f"From PID {sender}: {content}" for sender, content in msgs])
        messagebox.showinfo(f"Messages for PID {pid}", text)

    def configuration_dialog():
        max_proc = simpledialog.askinteger("Configuration", "Set max processes:",
                                           initialvalue=system_config["max_processes"], minvalue=1)
        if max_proc is not None:
            system_config["max_processes"] = max_proc

        messagebox.showinfo("Configuration",
                            f"Configuration updated:\nMax Processes = {system_config['max_processes']}")

    def queue_to_text(queue):
        sorted_queue = sorted(queue, key=lambda p: p['priority'])
        return [f"PID: {p['pid']} | {p['name']} | Priority: {p['priority']} | {p['state']}" for p in sorted_queue]

    def update_listbox(listbox, queue):
        listbox.delete(0, END)
        for item in queue_to_text(queue):
            listbox.insert(END, item)

    def update_running_label():
        if running_process:
            running_label.config(
                text=f"PID: {running_process['pid']} | {running_process['name']} | Priority: {running_process['priority']} | {running_process['state']}")
        else:
            running_label.config(text="No running process")

    def refresh_all():
        update_listbox(ready_listbox, ready_queue)
        update_listbox(blocked_listbox, blocked_queue)
        update_listbox(suspended_listbox, suspended_queue)
        update_running_label()

    def input_pid(prompt="Enter PID"):
        return simpledialog.askinteger("Input", prompt, parent=root, minvalue=100, maxvalue=999)

    def input_name_priority():
        name = simpledialog.askstring("Input", "Enter Process Name", parent=root)
        if not name or name.strip() == "":
            return None, None
        priority = simpledialog.askinteger("Input", "Enter Priority (lower is higher)", parent=root, minvalue=0)
        return name, priority


    Label(root, text="Process Management", bg="#1E1E2F", fg="white", font="Arial 18 bold")\
        .grid(row=0, column=0, columnspan=3, pady=10)

    Label(root, text="Ready Queue", fg="white", bg="#1E1E2F", font=("Arial", 12, "bold")).grid(row=2, column=0)
    Label(root, text="Blocked Queue", fg="white", bg="#1E1E2F", font=("Arial", 12, "bold")).grid(row=2, column=1)
    Label(root, text="Suspended Queue", fg="white", bg="#1E1E2F", font=("Arial", 12, "bold")).grid(row=2, column=2)

    ready_listbox = Listbox(root, width=40, height=10)
    ready_listbox.grid(row=3, column=0, padx=10, pady=5)
    blocked_listbox = Listbox(root, width=40, height=10)
    blocked_listbox.grid(row=3, column=1, padx=10, pady=5)
    suspended_listbox = Listbox(root, width=40, height=10)
    suspended_listbox.grid(row=3, column=2, padx=10, pady=5)

    Label(root, text="Running Process", fg="white", bg="#1E1E2F", font=("Arial", 12, "bold"))\
        .grid(row=4, column=0, columnspan=3, pady=(10, 0))
    running_label = Label(root, text="No running process", fg="yellow", bg="#1E1E2F", font=("Courier", 10))
    running_label.grid(row=5, column=0, columnspan=3)

    btn_frame = Frame(root, bg="#1E1E2F")
    btn_frame.grid(row=6, column=0, columnspan=3, pady=20)

    def create_dialog():
        name = simpledialog.askstring("Input", "Enter Process Name", parent=root)
        if not name or name.strip() == "":
            messagebox.showerror("Error", "Invalid name.")
            return
        priority = simpledialog.askinteger("Input", "Enter Priority (lower is higher)", parent=root, minvalue=0)
        if priority is None:
            messagebox.showerror("Error", "Invalid priority.")
            return
        arrival_time = simpledialog.askinteger("Input", "Enter Arrival Time", parent=root, minvalue=0)
        if arrival_time is None:
            arrival_time = 0
        burst_time = simpledialog.askinteger("Input", "Enter Burst Time", parent=root, minvalue=1)
        if burst_time is None:
            burst_time = 1
        owner = simpledialog.askstring("Input", "Enter Owner", parent=root)
        if not owner:
            owner = "User"
        memory_req = simpledialog.askinteger("Input", "Enter Memory requirement (KB)", parent=root, minvalue=1)
        if memory_req is None:
            memory_req = 100
        result = create_process(name, priority, owner, memory_req, arrival_time, burst_time)
        messagebox.showinfo("PCB Created",
                            f"{result}\n\nProcess Control Block:\nName: {name}\nPriority: {priority}\nArrival: {arrival_time}\nBurst: {burst_time}\nOwner: {owner}\nState: Ready")
        refresh_all()

    def destroy_dialog():
        pid = input_pid("Enter PID to destroy:")
        if pid:
            messagebox.showinfo("Result", destroy_process(pid))
            refresh_all()

    def suspend_dialog():
        pid = input_pid("Enter PID to suspend:")
        if pid:
            messagebox.showinfo("Result", suspend_process(pid))
            refresh_all()

    def resume_dialog():
        pid = input_pid("Enter PID to resume:")
        if pid:
            messagebox.showinfo("Result", resume_process(pid))
            refresh_all()

    def block_dialog():
        if running_process:
            pid = running_process["pid"]
            result = block_process(pid)
            messagebox.showinfo("Result", result)
            refresh_all()
        else:
            messagebox.showwarning("Warning", "No process is currently running to block.")

    def wakeup_dialog():
        pid = input_pid("Enter PID to wakeup:")
        if pid:
            messagebox.showinfo("Result", wakeup_process(pid))
            refresh_all()

    def dispatch_dialog():
        messagebox.showinfo("Result", dispatch_process())
        refresh_all()

    def change_priority_dialog():
        pid = input_pid("Enter PID to change priority:")
        if pid is None:
            return
        new_prio = simpledialog.askinteger("Input", "Enter new Priority:", parent=root, minvalue=0)
        if new_prio is not None:
            messagebox.showinfo("Result", change_priority(pid, new_prio))
            refresh_all()

    def auto_create():
        try:
            count = simpledialog.askinteger("Bulk Create", "How Many Processes you want to create?", parent=root, minvalue=1, maxvalue=50)
            if not count:
                return
            created = []
            for i in range(count):
                name = f"Process_{random.randint(1000,9999)}"
                priority = random.randint(0, 10)
                arrival_time = random.randint(0, 25)
                burst_time = random.randint(1, 25)
                owner = "User"
                memory_req = random.randint(50, 200)
                result = create_process(name, priority, owner, memory_req, arrival_time, burst_time)
                created.append(result)
            messagebox.showinfo("Bulk Created", f"{count} processes created!\n\n" + "\n".join(created[:5]) + ("\n..." if count > 5 else ""))
            refresh_all()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    buttons = [
        ("Create", create_dialog),
        ("Auto Create", auto_create),
        ("Destroy", destroy_dialog),
        ("Suspend", suspend_dialog),
        ("Resume", resume_dialog),
        ("Block", block_dialog),
        ("Wakeup", wakeup_dialog),
        ("Dispatch", dispatch_dialog),
        ("Change Priority", change_priority_dialog),
        ("Process Com", process_communication_dialog),
        ("View Messages", view_messages_dialog),
        ("Configuration", configuration_dialog),
    ]
    for i, (label, cmd) in enumerate(buttons):
        Button(btn_frame, text=label, command=cmd, bg="#3498DB", fg="white", width=14, height=1,
               font=("Arial", 11, "bold"), relief=RAISED, bd=5, cursor="hand2").grid(row=i // 4, column=i % 4, padx=10, pady=10)
    btn_frame1 = Frame(root, bg="#1E1E2F")
    btn_frame1.grid(row=7, column=0, columnspan=3)
    Button(btn_frame1, text="Back", bg="red", fg="white", font=("Arial", 10, "bold"),
           command=back, width=14, height=1, relief=RAISED, bd=5, cursor="hand2").grid(row=0, column=1)

    refresh_all()


def memory_management():
    clear_frame()

    def ma():
        clear_frame()
        process_names = [f"PID {p['pid']} - {p['name']} ({p['memory_req']} KB)" for p in ready_queue]
        selected_process = StringVar()
        if process_names:
            selected_process.set(process_names[0])
        else:
            selected_process.set("No process in Ready Queue")

        def get_selected_process_memory():
            idx = process_names.index(selected_process.get())
            return ready_queue[idx]['memory_req']

        def simulate_paging(process_memory, page_size):
            num_pages = (process_memory + page_size - 1) // page_size
            assigned_frames = [1, 3, 4, 6, 9]
            page_table = []
            internal_frag = 0

            for i in range(num_pages):
                is_last = i == num_pages - 1
                actual_size = process_memory % page_size if is_last and process_memory % page_size != 0 else page_size
                waste = page_size - actual_size if is_last else 0
                internal_frag += waste
                frame = assigned_frames[i] if i < len(assigned_frames) else -1
                page_table.append((i, f"{actual_size} KB", frame, f"{waste} KB"))

            return page_table, internal_frag

        def calculate():
            try:
                page_size = int(entry_page_size.get())
                process_memory = get_selected_process_memory()
                if page_size <= 0 or process_memory <= 0:
                    raise ValueError
            except Exception:
                messagebox.showerror("Invalid Input", "Please select a process and enter valid page size.")
                return

            page_table, internal_frag = simulate_paging(process_memory, page_size)
            result_text.config(state=NORMAL)
            result_text.delete(1.0, END)

            result_text.insert(END, f"📘 Page Size: {page_size} KB\n", "title")
            result_text.insert(END, f"📦 Process Memory: {process_memory} KB\n", "title")
            result_text.insert(END, f"📄 Pages Needed: {len(page_table)}\n\n", "title")
            result_text.insert(END, "{:<10} {:<12} {:<10} {:<15}\n".format("Page", "Page Size", "Frame", "Wasted"),
                               "header")

            for page in page_table:
                result_text.insert(END, "{:<10} {:<12} {:<10} {:<15}\n".format(*page), "data")

            result_text.insert(END, f"\n✅ Internal Fragmentation: {internal_frag} KB\n", "success")
            result_text.insert(END, f"✅ External Fragmentation: 0 KB (Paging avoids it)", "success")
            result_text.config(state=DISABLED)

        Label(root, text="Paging Simulator - OS Task 3.1", font=("Segoe UI", 18, "bold"),
              bg="#1E1E2F", fg="#00FFCC").pack(pady=15)

        if process_names:
            Frame(root, bg="#1E1E2F").pack(pady=5)
            Label(root, text="Select Process:", font=("Segoe UI", 12), bg="#1E1E2F", fg="white").pack()
            OptionMenu(root, selected_process, *process_names).pack(pady=5)
        else:
            Label(root, text="No process in Ready Queue.", font=("Segoe UI", 12), bg="#1E1E2F", fg="red").pack()

        input_frame = Frame(root, bg="#1E1E2F")
        input_frame.pack(pady=10)
        Label(input_frame, text="Page Size (KB):", font=("Segoe UI", 12), bg="#1E1E2F", fg="white").grid(row=0,
                                                                        column=0, padx=10, pady=10, sticky=E)
        entry_page_size = Entry(input_frame, font=("Segoe UI", 12), width=15, bg="#2A2A3B", fg="white",
                                insertbackground="white", relief=FLAT)
        entry_page_size.grid(row=0, column=1)

        Button(root, text="🔍 Calculate", command=calculate, font=("Segoe UI", 12), bg="#00AA88", fg="white",
               activebackground="#00FFCC", padx=10, pady=5, cursor="hand2", relief=RAISED, bd=5).pack(pady=10)

        result_text = Text(root, height=16, width=80, font=("Consolas", 10), bg="#111122", fg="white",
                           insertbackground="white", relief=FLAT)
        result_text.tag_config("title", foreground="#00FFCC", font=("Consolas", 10, "bold"))
        result_text.tag_config("header", foreground="#FFD700", font=("Consolas", 10, "bold"))
        result_text.tag_config("data", foreground="white")
        result_text.tag_config("success", foreground="#00FF00", font=("Consolas", 10, "bold"))
        result_text.pack(pady=10)
        result_text.config(state=DISABLED)

        Button(root, text="Back", command=memory_management, bg="red", fg="white",
               font=("Arial", 12, "bold"), relief=RAISED, bd=3, cursor="hand2").pack(pady=5)

    def lru():
        clear_frame()


        process_names = [f"PID {p['pid']} - {p['name']} ({p['memory_req']} KB)" for p in ready_queue]
        selected_process = StringVar()
        if process_names:
            selected_process.set(process_names[0])
        else:
            selected_process.set("No process in Ready Queue")

        def get_selected_process():
            idx = process_names.index(selected_process.get())
            return ready_queue[idx]

        def lru_page_replacement(pages, capacity):
            memory = []
            page_faults = 0
            page_order = []
            result = []

            for page in pages:
                state = ""
                if page not in memory:
                    page_faults += 1
                    if len(memory) < capacity:
                        memory.append(page)
                    else:
                        lru = page_order.pop(0)
                        memory.remove(lru)
                        memory.append(page)
                    state = f"Page {page} → FAULT"
                else:
                    state = f"Page {page} → HIT"
                    page_order.remove(page)
                page_order.append(page)
                result.append((list(memory), state))

            return result, page_faults

        def calculate_lru():
            listbox.delete(0, END)
            try:
                capacity = int(entry_capacity.get())
                process = get_selected_process()
                num_pages = max(1, process['memory_req'] // 10)
                pages = [random.randint(0, num_pages - 1) for _ in range(num_pages * 2)]
            except Exception:
                final_result_label.config(text="Invalid input.")
                return

            results, faults = lru_page_replacement(pages, capacity)
            for i, (mem, state) in enumerate(results):
                listbox.insert(END, f"Step {i + 1}: Memory: {mem} | {state}")

            final_result_label.config(
                text=f" Total Page Faults: {faults}\nReference String: {' '.join(map(str, pages))}", fg="lightgreen"
            )

        Label(root, text="LRU Page Replacement", font=("Arial", 20), fg="white", bg="#1E1E2F").pack(pady=10)

        if process_names:
            Frame(root, bg="#1E1E2F").pack(pady=5)
            Label(root, text="Select Process:", font=("Segoe UI", 12), bg="#1E1E2F", fg="white").pack()
            OptionMenu(root, selected_process, *process_names).pack(pady=5)
        else:
            Label(root, text="No process in Ready Queue.", font=("Segoe UI", 12), bg="#1E1E2F", fg="red").pack()

        frame_input = Frame(root, bg="#1E1E2F")
        frame_input.pack()
        Label(frame_input, text="Number of Frames:", font=("Arial", 12), fg="white", bg="#1E1E2F").grid(row=0, column=0,
                                                                                                        padx=5, pady=5,
                                                                                                        sticky=E)
        entry_capacity = Entry(frame_input, width=10)
        entry_capacity.grid(row=0, column=1, padx=5, pady=5)

        Button(root, text="Run LRU Algorithm", command=calculate_lru, bg="#444", fg="white", font=("Arial", 12),
               cursor="hand2", relief=RAISED, bd=5).pack(pady=20)

        frame_listbox = Frame(root)
        frame_listbox.pack()
        scrollbar = Scrollbar(frame_listbox)
        scrollbar.pack(side=RIGHT, fill=Y)
        listbox = Listbox(frame_listbox, width=80, height=10, yscrollcommand=scrollbar.set, font=("Courier", 10))
        listbox.pack(side=LEFT, fill=BOTH)
        scrollbar.config(command=listbox.yview)
        final_result_label = Label(root, text="", font=("Arial", 14), fg="white", bg="#1e1e1e")
        final_result_label.pack(pady=10)
        Button(root, text="Back", bg="red", fg="white", height=2, width=10, font="Arial 12 bold", relief=RAISED, bd=5,
               command=memory_management, cursor="hand2").pack(pady=10)

    Label(root, text="Memory Management", bg="#1E1E2F", fg="white", font=("Arial", 22, "bold"), pady=20).pack()
    frame1 = Frame(root, bg="black")
    photo = PhotoImage(file=r"OS project pic\4.png", height=180, width=290)
    pic = Label(frame1, image=photo, bg="black")
    pic.image = photo
    pic.pack()
    frame1.pack()
    f = Frame(root, bg="#1E1E2F")
    f.pack()
    styled_button2(f, "Memory Allocation", ma)
    styled_button2(f, "LRU", lru)
    Button(root, text="Back", bg="red", fg="white", height=2, width=10, font="Arial 12 bold", relief=RAISED, bd=5,
           command=main2, cursor="hand2").pack(pady=10)

def io_management():
    clear_frame()
    input_devices = ["Keyboard", "Mouse", "Scanner", "Webcam", "Microphone", "Joystick"]
    output_devices = ["Monitor", "Printer", "External Drive", "Network Adapter"]
    SAVE_FILE = "selected_devices.txt"

    def back():
        main2()

    Label(root, text="I/O Device Management", font=("Arial", 18, "bold"), bg="#1E1E2F", fg="white").pack(pady=10)
    device_vars = {}
    frame = Frame(root, bg="#1E1E2F")
    frame.pack()

    input_frame = LabelFrame(frame, text="Input Devices", padx=10, pady=10, bg="white", font=("Arial", 12, "bold"))
    input_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

    for idx, device in enumerate(input_devices):
        var = BooleanVar()
        Checkbutton(input_frame, text=device, variable=var, font=("Arial", 11), bg="white").grid(row=idx // 2,
                                                                                                 column=idx % 2,
                                                                                                 sticky="w")

        device_vars[device] = var

    output_frame = LabelFrame(frame, text="Output Devices", padx=10, pady=10, bg="white", font=("Arial", 12, "bold"))
    output_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
    for idx, device in enumerate(output_devices):
        var = BooleanVar()
        Checkbutton(output_frame, text=device, variable=var, font=("Arial", 11), bg="white").grid(row=idx // 2,
                                                                                                  column=idx % 2,
                                                                                                  sticky="w")
        device_vars[device] = var

    def show_selected():
        selected = [device for device, var in device_vars.items() if var.get()]
        if selected:
            messagebox.showinfo("Selected Devices", "\n".join(selected))
        else:
            messagebox.showwarning("No Selection", "No devices selected!")

    def save_selected():
        selected = [device for device, var in device_vars.items() if var.get()]
        try:
            with open(SAVE_FILE, 'w') as file:
                for device in selected:
                    file.write(device + "\n")
            messagebox.showinfo("Saved", f"Selected devices saved to {SAVE_FILE}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def load_selected(device_vars):
        try:
            with open(SAVE_FILE, 'r') as file:
                selected_devices = file.read().splitlines()
            for device, var in device_vars.items():
                var.set(device in selected_devices)
            messagebox.showinfo("Loaded", "Device selection loaded successfully.")
        except FileNotFoundError:
            messagebox.showerror("Error", f"No save file found: {SAVE_FILE}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def assign_devices_to_process():
        pid = simpledialog.askinteger("Assign Devices", "Enter PID to assign devices:", parent=root, minvalue=100, maxvalue=999)
        if pid is None:
            return
        process = None
        for queue in [ready_queue, blocked_queue, suspended_queue]:
            for p in queue:
                if p["pid"] == pid:
                    process = p
                    break
        global running_process
        if running_process and running_process["pid"] == pid:
            running_process["devices"] = [device for device, var in device_vars.items() if var.get()]
            running_process["state"] = BLOCKED
            blocked_queue.append(running_process)
            running_process = None
            messagebox.showinfo("Assigned", f"Devices assigned to PID {pid} and process moved to Blocked (I/O) state.")
            return
        if not process:
            messagebox.showerror("Error", "PID not found in PCB.")
            return
        selected = [device for device, var in device_vars.items() if var.get()]
        process["devices"] = selected
        messagebox.showinfo("Assigned", f"Devices assigned to PID {pid}:\n" + "\n".join(selected) if selected else "No devices assigned.")

    f1 = Frame(root, bg="#1E1E2F")
    f1.pack()
    styled_button2(f1, "Show Selected", show_selected)
    styled_button2(f1, "Save Selected", save_selected)
    f2 = Frame(root, bg="#1E1E2F")
    f2.pack()
    styled_button2(f2, "Load Selected", lambda: load_selected(device_vars))
    styled_button2(f2, "Assign to Process", assign_devices_to_process)  # <-- Add this button
    Button(root, text="Back", bg="red", fg="white", height=2, width=10, font="Arial 12 bold", command=back,
           relief=RAISED, bd=5, cursor="hand2").pack(pady=10)


def p_scheduling():
    clear_frame()

    def fcfs():
        clear_frame()
        Label(root, text="FCFS Scheduling", font=('Arial', 14, 'bold'), bg="#1E1E2F", fg="white").pack(pady=10)

        processes = []
        for p in ready_queue:
            arrival = p.get("arrival_time", 0)
            burst = p.get("burst_time", 1)
            processes.append([p["pid"], arrival, burst])

        if not processes:
            Label(root, text="No processes in PCB Ready Queue.", fg="red", bg="#1E1E2F").pack(pady=10)
            Button(root, text="Back", bg="red", fg="white", height=2, width=10, font="Arial 12 bold",
                   command=p_scheduling, relief=RAISED, bd=5, cursor="hand2").pack(pady=10)
            return

        processes.sort(key=lambda x: x[1])
        current_time = 0
        results = []
        total_tat = 0
        total_wt = 0
        gantt_chart = []

        for p in processes:
            pid, arrival, burst = p
            # Handle idle time
            if current_time < arrival:
                # Add idle period to Gantt chart
                gantt_chart.append(("IDLE", current_time, arrival))
                current_time = arrival
            start_time = current_time
            completion = current_time + burst
            turnaround = completion - arrival
            waiting = turnaround - burst
            current_time = completion

            gantt_chart.append((pid, start_time, completion))
            total_tat += turnaround
            total_wt += waiting
            results.append((pid, arrival, burst, completion, turnaround, waiting))

        avg_tat = round(total_tat / len(processes), 2)
        avg_wt = round(total_wt / len(processes), 2)

        output_frame = Frame(root, bg="#1E1E2F")
        output_frame.pack(pady=10)

        headers = ["PID", "Arrival", "Burst", "Completion", "Turnaround", "Waiting"]
        for col, text in enumerate(headers):
            Label(output_frame, text=text, borderwidth=1, relief="solid", width=12, bg="lightgray").grid(row=0,
                                                                                                         column=col)

        for row, result in enumerate(results, start=1):
            for col, value in enumerate(result):
                Label(output_frame, text=value, borderwidth=1, relief="solid", width=12).grid(row=row, column=col)

        Label(output_frame, text=f"Average TAT: {avg_tat}", font=('Arial', 12, 'bold'), bg="#1E1E2F", fg="white") \
            .grid(row=row + 1, column=0, columnspan=3, pady=10)
        Label(output_frame, text=f"Average WT: {avg_wt}", font=('Arial', 12, 'bold'), bg="#1E1E2F", fg="white") \
            .grid(row=row + 1, column=3, columnspan=3, pady=10)

        canvas_frame = Frame(root)
        canvas_frame.pack(pady=10, fill=X)

        h_scroll = Scrollbar(canvas_frame, orient=VERTICAL)
        h_scroll.pack(side=RIGHT, fill=Y)
        h_scroll = Scrollbar(canvas_frame, orient=HORIZONTAL)
        h_scroll.pack(side=BOTTOM, fill=X)

        canvas = Canvas(canvas_frame, width=800, height=80, bg="white", xscrollcommand=h_scroll.set)
        canvas.pack(side=TOP, fill=X)

        h_scroll.config(command=canvas.xview)

        unit_width = 25
        x_start = 10
        y_start = 40
        height = 40
        for pid, start, end in gantt_chart:
            width = (end - start) * unit_width
            color = "gray" if pid == "IDLE" else "lightgreen"  # or other color for idle
            canvas.create_rectangle(x_start, y_start, x_start + width, y_start + height, fill=color, outline="black")
            canvas.create_text(x_start + width / 2, y_start + height / 2, text=pid)
            canvas.create_text(x_start, y_start + height + 15, text=str(start))
            x_start += width
        canvas.create_text(x_start, y_start + height + 15, text=str(gantt_chart[-1][2]))

        canvas.config(scrollregion=canvas.bbox("all"))

        Button(root, text="Back", bg="red", fg="white", height=2, width=10, font="Arial 12 bold",
               command=p_scheduling, relief=RAISED, bd=5, cursor="hand2").pack(pady=10)

    def sjf():
        clear_frame()
        Label(root, text="Shortest Job First (SJF) Scheduling", font=('Arial', 14, 'bold'), bg="#1E1E2F",
                  fg="white").pack(pady=10)

        processes = []
        for p in ready_queue:
            arrival = p.get("arrival_time", 0)
            burst = p.get("burst_time", 1)
            processes.append([p["pid"], arrival, burst])

        if not processes:
            Label(root, text="No processes in PCB Ready Queue.", fg="red", bg="#1E1E2F").pack(pady=10)
            Button(root, text="Back", bg="red", fg="white", height=2, width=10, font="Arial 12 bold",
                       command=p_scheduling,
                       relief=RAISED, bd=5, cursor="hand2").pack(pady=10)
            return

        completed = []
        current_time = 0
        total_tat = 0
        total_wt = 0
        gantt_chart = []
        results = []

        while len(completed) < len(processes):
            available = [p for p in processes if p not in completed and p[1] <= current_time]
            if available:
                shortest = min(available, key=lambda x: x[2])
                pid, arrival, burst = shortest
                start_time = current_time
                completion = current_time + burst
                turnaround = completion - arrival
                waiting = turnaround - burst
                current_time = completion
                completed.append(shortest)
                gantt_chart.append((pid, start_time, completion))
                total_tat += turnaround
                total_wt += waiting
                results.append((pid, arrival, burst, completion, turnaround, waiting))
            else:
                # Handle idle time
                next_arrival = min([p[1] for p in processes if p not in completed])
                gantt_chart.append(("IDLE", current_time, next_arrival))
                current_time = next_arrival

        avg_tat = round(total_tat / len(processes), 2)
        avg_wt = round(total_wt / len(processes), 2)

        output_frame = Frame(root, bg="#1E1E2F")
        output_frame.pack(pady=10)

        headers = ["PID", "Arrival", "Burst", "Completion", "Turnaround", "Waiting"]
        for col, text in enumerate(headers):
            Label(output_frame, text=text, borderwidth=1, relief="solid", width=12, bg="lightgray").grid(row=0,
                                                                                                             column=col)

        for row, result in enumerate(results, start=1):
            for col, value in enumerate(result):
                Label(output_frame, text=value, borderwidth=1, relief="solid", width=12).grid(row=row, column=col)

        Label(output_frame, text=f"Average TAT: {avg_tat}", font=('Arial', 12, 'bold'), bg="#1E1E2F", fg="white") \
                .grid(row=row + 1, column=0, columnspan=3, pady=10)
        Label(output_frame, text=f"Average WT: {avg_wt}", font=('Arial', 12, 'bold'), bg="#1E1E2F", fg="white") \
                .grid(row=row + 1, column=3, columnspan=3, pady=10)

        canvas_frame = Frame(root)
        canvas_frame.pack(pady=10, fill=X)
        x_scroll = Scrollbar(canvas_frame, orient=HORIZONTAL)
        x_scroll.pack(side=BOTTOM, fill=X)
        canvas = Canvas(canvas_frame, width=800, height=120, bg="white", xscrollcommand=x_scroll.set)
        canvas.pack(side=TOP, fill=X)
        x_scroll.config(command=canvas.xview)

        unit_width = 25
        x_start = 10
        y_start = 40
        height = 40
        for pid, start, end in gantt_chart:
            width = (end - start) * unit_width
            color = "gray" if pid == "IDLE" else "lightgreen"
            canvas.create_rectangle(x_start, y_start, x_start + width, y_start + height, fill=color, outline="black")
            canvas.create_text(x_start + width / 2, y_start + height / 2, text=pid)
            canvas.create_text(x_start, y_start + height + 15, text=str(start))
            x_start += width
        canvas.create_text(x_start, y_start + height + 15, text=str(gantt_chart[-1][2]))
        canvas.config(scrollregion=canvas.bbox("all"))

        Button(root, text="Back", bg="red", fg="white", height=2, width=10, font="Arial 12 bold",
                   command=p_scheduling, relief=RAISED, bd=5, cursor="hand2").pack(pady=10)

    def priority():
        clear_frame()
        Label(root, text="Priority Scheduling (Non-Preemptive)", font=('Arial', 14, 'bold'), bg="#1E1E2F",
                  fg="white").pack(pady=10)

        processes = []
        for p in ready_queue:
            arrival = p.get("arrival_time", 0)
            burst = p.get("burst_time", 1)
            prio = p.get("priority", 0)
            processes.append([p["pid"], arrival, burst, prio])

        if not processes:
            Label(root, text="No processes in PCB Ready Queue.", fg="red", bg="#1E1E2F").pack(pady=10)
            Button(root, text="Back", bg="red", fg="white", height=2, width=10, font="Arial 12 bold",
                       command=p_scheduling, relief=RAISED, bd=5, cursor="hand2").pack(pady=10)
            return

        completed = []
        current_time = 0
        total_tat = 0
        total_wt = 0
        gantt_chart = []
        results = []

        while len(completed) < len(processes):
            available = [p for p in processes if p not in completed and p[1] <= current_time]
            if available:
                highest_priority = min(available, key=lambda x: (x[3], x[1]))
                pid, arrival, burst, prio = highest_priority
                start_time = current_time
                completion = current_time + burst
                turnaround = completion - arrival
                waiting = turnaround - burst
                current_time = completion
                completed.append(highest_priority)
                gantt_chart.append((pid, start_time, completion))
                total_tat += turnaround
                total_wt += waiting
                results.append((pid, arrival, burst, prio, completion, turnaround, waiting))
            else:
                # Handle idle time
                next_arrival = min([p[1] for p in processes if p not in completed])
                gantt_chart.append(("IDLE", current_time, next_arrival))
                current_time = next_arrival

        avg_tat = round(total_tat / len(processes), 2)
        avg_wt = round(total_wt / len(processes), 2)

        output_frame = Frame(root, bg="#1E1E2F")
        output_frame.pack(pady=10)

        headers = ["PID", "Arrival", "Burst", "Priority", "Completion", "Turnaround", "Waiting"]
        for col, text in enumerate(headers):
            Label(output_frame, text=text, borderwidth=1, relief="solid", width=12, bg="lightgray").grid(row=0,
                                                                                                             column=col)

        for row, result in enumerate(results, start=1):
            for col, value in enumerate(result):
                Label(output_frame, text=value, borderwidth=1, relief="solid", width=12).grid(row=row, column=col)

        Label(output_frame, text=f"Average TAT: {avg_tat}", font=('Arial', 12, 'bold'), bg="#1E1E2F", fg="white") \
                .grid(row=row + 1, column=0, columnspan=4, pady=10)
        Label(output_frame, text=f"Average WT: {avg_wt}", font=('Arial', 12, "bold"), bg="#1E1E2F", fg="white") \
                .grid(row=row + 1, column=4, columnspan=3, pady=10)

        canvas_frame = Frame(root)
        canvas_frame.pack(pady=10, fill=X)
        x_scroll = Scrollbar(canvas_frame, orient=HORIZONTAL)
        x_scroll.pack(side=BOTTOM, fill=X)
        canvas = Canvas(canvas_frame, width=800, height=120, bg="white", xscrollcommand=x_scroll.set)
        canvas.pack(side=TOP, fill=X)
        x_scroll.config(command=canvas.xview)

        unit_width = 25
        x_start = 10
        y_start = 40
        height = 40
        for pid, start, end in gantt_chart:
            width = (end - start) * unit_width
            color = "gray" if pid == "IDLE" else "orange"
            canvas.create_rectangle(x_start, y_start, x_start + width, y_start + height, fill=color, outline="black")
            canvas.create_text(x_start + width / 2, y_start + height / 2, text=pid)
            canvas.create_text(x_start, y_start + height + 15, text=str(start))
            x_start += width
        canvas.create_text(x_start, y_start + height + 15, text=str(gantt_chart[-1][2]))
        canvas.config(scrollregion=canvas.bbox("all"))

        Button(root, text="Back", bg="red", fg="white", height=2, width=10, font="Arial 12 bold",
                   command=p_scheduling, relief=RAISED, bd=5, cursor="hand2").pack(pady=10)

    def round_robin():
        clear_frame()
        Label(root, text="Round Robin Scheduling", font=('Arial', 14, 'bold'), bg="#1E1E2F", fg="white").pack(pady=10)

        processes = []
        for p in ready_queue:
            arrival = p.get("arrival_time", 0)
            burst = p.get("burst_time", 1)
            processes.append([p["pid"], arrival, burst])

        if not processes:
            Label(root, text="No processes in PCB Ready Queue.", fg="red", bg="#1E1E2F").pack(pady=10)
            Button(root, text="Back", bg="red", fg="white", height=2, width=10, font="Arial 12 bold",
                       command=p_scheduling, relief=RAISED, bd=5, cursor="hand2").pack(pady=10)
            return

        tq_frame = Frame(root, bg="#1E1E2F")
        tq_frame.pack(pady=5)
        Label(tq_frame, text="Enter Time Quantum:", font=('Arial', 12), bg="#1E1E2F", fg="white").pack(side=LEFT, padx=5)
        quantum_entry = Entry(tq_frame, font=('Arial', 12), width=5)
        quantum_entry.pack(side=LEFT, padx=5)
        quantum_entry.insert(0, "2")

        output_frame = Frame(root, bg="#1E1E2F")
        output_frame.pack(pady=10)

        canvas_frame = Frame(root)
        canvas_frame.pack(pady=10, fill=X)
        x_scroll = Scrollbar(canvas_frame, orient=HORIZONTAL)
        x_scroll.pack(side=BOTTOM, fill=X)
        canvas = Canvas(canvas_frame, width=800, height=120, bg="white", xscrollcommand=x_scroll.set)
        canvas.pack(side=TOP, fill=X)
        x_scroll.config(command=canvas.xview)

        def rr_scheduling(time_quantum, processes):
            for p in processes:
                p.append(p[2])

            rr_queue = []
            current_time = 0
            completed = []
            gantt_chart = []
            results = []

            while len(completed) < len(processes):
                for p in processes:
                    if p not in rr_queue and p not in completed and p[1] <= current_time:
                        rr_queue.append(p)

                if not rr_queue:
                    # Handle idle time
                    future_arrivals = [p[1] for p in processes if p not in completed and p[1] > current_time]
                    if future_arrivals:
                        next_arrival = min(future_arrivals)
                        gantt_chart.append(("IDLE", current_time, next_arrival))
                        current_time = next_arrival
                    else:
                        break
                    continue

                p = rr_queue.pop(0)
                pid, arrival, burst, remaining = p
                start_time = current_time
                exec_time = min(time_quantum, remaining)
                current_time += exec_time
                p[3] -= exec_time
                gantt_chart.append((pid, start_time, current_time))

                for q in processes:

                    if q not in rr_queue and q not in completed and q[1] > start_time and q[1] <= current_time:
                        rr_queue.append(q)

                if p[3] > 0:
                    rr_queue.append(p)
                else:
                    completed.append(p)
                    turnaround = current_time - arrival
                    waiting = turnaround - burst
                    results.append((pid, arrival, burst, current_time, turnaround, waiting))

            n = len(processes)
            avg_tat = round(sum(t[4] for t in results) / n, 2)
            avg_wt = round(sum(t[5] for t in results) / n, 2)

            return results, gantt_chart, avg_tat, avg_wt

        def display_rr():
            try:
                import copy
                time_quantum = int(quantum_entry.get())
                rr_processes = copy.deepcopy(processes)
                results, gantt_chart, avg_tat, avg_wt = rr_scheduling(time_quantum, rr_processes)

                for widget in output_frame.winfo_children():
                    widget.destroy()
                canvas.delete("all")

                headers = ["PID", "Arrival", "Burst", "Completion", "Turnaround", "Waiting"]
                for col, text in enumerate(headers):
                    Label(output_frame, text=text, borderwidth=1, relief="solid", width=12, bg="lightgray").grid(
                            row=0, column=col)

                for row, result in enumerate(results, start=1):
                    for col, value in enumerate(result):
                        Label(output_frame, text=value, borderwidth=1, relief="solid", width=12).grid(row=row,
                                                                                                          column=col)

                Label(output_frame, text=f"Average TAT: {avg_tat}", font=('Arial', 12, 'bold'), bg="#1E1E2F",
                          fg="white") \
                        .grid(row=row + 1, column=0, columnspan=3, pady=10)
                Label(output_frame, text=f"Average WT: {avg_wt}", font=('Arial', 12, 'bold'), bg="#1E1E2F",
                          fg="white") \
                        .grid(row=row + 1, column=3, columnspan=3, pady=10)

                unit_width = 25
                x_start = 10
                y_start = 40
                height = 40
                for pid, start, end in gantt_chart:
                    width = (end - start) * unit_width
                    color = "gray" if pid == "IDLE" else "lightblue"
                    canvas.create_rectangle(x_start, y_start, x_start + width, y_start + height, fill=color,
                                            outline="black")
                    canvas.create_text(x_start + width / 2, y_start + height / 2, text=pid)
                    canvas.create_text(x_start, y_start + height + 15, text=str(start))
                    x_start += width
                canvas.create_text(x_start, y_start + height + 15, text=str(gantt_chart[-1][2]))
                canvas.config(scrollregion=canvas.bbox("all"))

            except Exception as e:
                messagebox.showerror("Error", str(e))

        button_frame = Frame(root, bg="#1E1E2F")
        button_frame.pack(pady=10)
        styled_button2(button_frame, "Run Round Robin", display_rr)
        Button(button_frame, text="Back", bg="red", fg="white", height=2, width=10, font="Arial 12 bold",
                   relief=RAISED, bd=5, command=p_scheduling, cursor="hand2").pack(pady=5, padx=30)

    Label(root, text="Process Scheduling", bg="#1E1E2F", fg="white", font="Arial 18 bold").pack(pady=20)
    frame2 = Frame(root, bg="black")
    photo = PhotoImage(file=r"OS project pic\1.png", height=130, width=430)
    pic = Label(frame2, image=photo, bg="black")
    pic.image = photo
    pic.pack()
    frame2.pack()
    frame1 = Frame(root, bg="#1E1E2F")
    frame1.pack()
    f1 = Frame(root, bg="#1E1E2F")
    f1.pack()
    styled_button2(f1, "FCFS", fcfs)
    styled_button2(f1, "SJF", sjf)
    f2 = Frame(root, bg="#1E1E2F")
    f2.pack()
    styled_button2(f2, "Priority", priority)
    styled_button2(f2, "Round Robin", round_robin)
    Button(root, text="Back", bg="red", fg="white", height=2, width=10, font="Arial 12 bold", command=main2,
           relief=RAISED, bd=5).pack(pady=10)


def other():
    clear_frame()

    def run_synchronization_gui():
        clear_frame()
        semaphore = threading.Semaphore(1)
        shared_output = StringVar(value="Shared Resource Output...")
        shared_resource = ""
        status_label = Label(root, text="Idle", font=("Arial", 13, "bold"), bg="#1E1E2F", fg="white")

        Label(root, text="🔒 Synchronization with Semaphores", font=("Arial", 22, "bold"),
              bg="#1E1E2F", fg="#00FFD0", pady=10).pack(fill=X)

        frame = Frame(root, bg="#1E1E2F")
        frame.pack(pady=20)

        progress_frame = Frame(root, bg="#1E1E2F")
        progress_frame.pack(pady=10)
        canvas = Canvas(progress_frame, width=320, height=30, bg="#181828", bd=0, highlightthickness=0)
        canvas.pack()
        bar = canvas.create_rectangle(0, 0, 0, 30, fill="#00FF99")
        percentage_label = Label(progress_frame, text="0%", font=("Arial", 12, "bold"), bg="#1E1E2F", fg="#00FFD0")
        percentage_label.pack()

        Label(root, text="Shared Output:", font=("Arial", 13, "bold"), bg="#1E1E2F", fg="#FFD700").pack(pady=(15, 0))
        Label(root, textvariable=shared_output, font=("Consolas", 13, "bold"), bg="#1E1E2F", fg="#00FFD0", width=40,
              height=2, relief=RIDGE, bd=2).pack(pady=5)

        status_label.pack(pady=10)

        log_label = Label(root, text="Process Log:", font=("Arial", 12, "bold"), bg="#1E1E2F", fg="#FFD700")
        log_label.pack()
        log_box = Listbox(root, width=50, height=4, font=("Consolas", 11), bg="#1E1E2F", fg="#00FFD0", bd=2,
                          relief=RIDGE)
        log_box.pack(pady=5)

        def update_progress(total_steps):
            for i in range(total_steps + 1):
                width = (320 / total_steps) * i
                canvas.coords(bar, 0, 0, width, 30)
                percentage_label.config(text=f"{int((i / total_steps) * 100)}%")
                root.update_idletasks()
                time.sleep(random.uniform(0.1, 0.8))
            percentage_label.config(text="Done!")

        def process(name):
            def run():
                nonlocal shared_resource
                try:
                    waiting_text = f"{name} waiting..."
                    status_label.config(text=f"{waiting_text}", fg="#FFB300")
                    log_box.insert(END, waiting_text)

                    semaphore.acquire()

                    items = log_box.get(0, END)
                    for i, item in enumerate(items):
                        if item == waiting_text:
                            log_box.delete(i)
                            break

                    status_label.config(text=f"{name} entered Critical Section", fg="#00FF99")
                    threading.Thread(target=update_progress, args=(5,), daemon=True).start()

                    for i in range(5):
                        shared_resource = f"{name} writing {i + 1}"
                        shared_output.set(shared_resource)
                        time.sleep(random.uniform(0.2, 1.0))
                    status_label.config(text=f"{name} exiting Critical Section", fg="#FFD700")

                finally:
                    semaphore.release()
                    status_label.config(text="Idle", fg="white")

            threading.Thread(target=run, daemon=True).start()

        Button(frame, text="Run Process A", command=lambda: process("Process A"), bg="#3498DB", fg="white",
               width=16, height=2, font=("Arial", 12, "bold"), relief=RAISED, bd=5, cursor="hand2").grid(row=0,
                                                                                                         column=0,
                                                                                                         padx=20)
        Button(frame, text="Run Process B", command=lambda: process("Process B"), bg="#E67E22", fg="white",
               width=16, height=2, font=("Arial", 12, "bold"), relief=RAISED, bd=5, cursor="hand2").grid(row=0,
                                                                                                         column=1,
                                                                                                         padx=20)
        Label(root, text="Shared Output:", font=("Arial", 12), bg="#202030", fg="lightgray").pack(pady=10)
        Label(root, textvariable=shared_output, font=("Consolas", 12), bg="#1C1C2B", fg="cyan", width=40,
              height=2).pack()
        Button(root, text="Back", command=other, bg="red", fg="white", width=15, height=2, cursor="hand2", relief=RAISED
               , bd=5, font=("Arial", 12, "bold")).pack(pady=10)
    Label(root, text="Other", bg="#1E1E2F", fg="white", font="Arial 18 bold").pack(pady=20)
    f2 = Frame(root, bg="#1E1E2F")
    f2.pack()
    styled_button1(f2, "Synchronization", lambda: [clear_frame(), run_synchronization_gui()])
    Button(root, text="Exit", bg="red", fg="white", height=2, width=10, font="Arial 12 bold", command=main2,
           relief=RAISED, bd=5, cursor="hand2").pack(pady=10)


def main2():
    clear_frame()
    taskbar = StringVar()
    taskbar.set("Contact\t\t\tPrivacy policy\t\tTerms & Conditions")
    s_bar = Label(root, textvariable=taskbar)
    s_bar.pack(side=BOTTOM, fill=X)
    s_bar = Label(root, text="2025 All Reserved Licence")
    s_bar.pack(side=BOTTOM, fill=X)

    Label(root, text="Control Panel UI", bg="#1E1E2F", fg="white", font=("Arial", 24, "bold"), pady=10).pack()
    frame1 = Frame(root, bg="black")
    photo = PhotoImage(file=r"OS project pic\0.png", height=85, width=400)
    pic = Label(frame1, image=photo, bg="black")
    pic.image = photo
    pic.pack()
    frame1.pack()
    frame1 = Frame(root, bg="#1E1E2F")
    frame1.pack()
    f1 = Frame(root, bg="#1E1E2F")
    f1.pack()
    styled_button1(f1, "Process Management", command=process_management)
    styled_button1(f1, "Memory Management", command=memory_management)
    styled_button1(f1, "I/O Management", command=io_management)
    f2 = Frame(root, bg="#1E1E2F")
    f2.pack()
    styled_button1(f2, "Process Scheduling", command=p_scheduling)
    styled_button1(f2, "Other", command=other)
    Button(root, text="Exit", bg="red", fg="white", height=2, width=10, font="Arial 12 bold", command=root.quit,
           relief=RAISED, bd=5, cursor="hand2").pack(pady=10)


main2()
root.mainloop()
