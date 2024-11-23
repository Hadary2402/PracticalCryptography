import socket
import tkinter as tk
import tkinter
from PIL import Image, ImageTk
from tkinter import END, Toplevel, ttk
from tkinter import filedialog
from tkinter import messagebox
import tkinter.scrolledtext
from tkinter import simpledialog
import threading
import hashlib  # Import hashlib for SHA-256 hashing

# ==================================================

# Connection Data
host = '127.0.0.1'   # host IP address
port = 5555


class App(tk.Tk):

    UserName = ''
    
    def __init__(self):
        super().__init__()

        # connecting to server
        try:
            self.sock = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
            self.sock.connect((host, port))

        except ConnectionRefusedError:
            messagebox.showinfo(title="Error Code: 106", message="Unable to connect to server. Server may be offline or you may not be connected to the internet.")
            print("Server is offline , try again later.")
            return

        # constructing the main window
        WIDTH = 500
        HEIGHT = 400
        self.geometry(f"{WIDTH}x{HEIGHT}")
        self.title("Chat Room")
        self.protocol("WM_DELETE_WINDOW", self.stop)

        self.user = None
        self.image_extension = None
        self.image_path = None

        # getting the app icon
        global app_icon
        app_icon = Image.open('images/1.png')
        app_icon = ImageTk.PhotoImage(app_icon)
        self.iconphoto(False, app_icon)

        # getting background photo and other photos
        self.background = Image.open("images/10.jpg")
        self.background = self.background.resize((500, 400), Image.LANCZOS)
        self.background = ImageTk.PhotoImage(self.background)

        self.login_image = Image.open(r'images/3.png')
        self.login_image = self.login_image.resize((25, 25), Image.LANCZOS)
        self.login_image = ImageTk.PhotoImage(self.login_image)

        self.sign_up_image = Image.open(r'images/4.png')
        self.sign_up_image = self.sign_up_image.resize((25, 25), Image.LANCZOS)
        self.sign_up_image = ImageTk.PhotoImage(self.sign_up_image)

        # making two tabs to login or sign-up
        self.tabControl = ttk.Notebook(self)

        self.tab1 = ttk.Frame(self.tabControl)
        self.tab2 = ttk.Frame(self.tabControl)

        self.bgLabel1 = ttk.Label(self.tab1, image=self.background)
        self.bgLabel1.place(x=0, y=0)

        self.bgLabel2 = ttk.Label(self.tab2, image=self.background)
        self.bgLabel2.place(x=0, y=0)

        self.tabControl.add(self.tab1, text='Login', image=self.login_image, compound="left")
        self.tabControl.add(self.tab2, text='Sign up', image=self.sign_up_image, compound="left")
        self.tabControl.pack(expand=1, fill='both')

        # ------------------ Login Tab ----------------------

        self.label1 = ttk.Label(self.tab1, image=self.login_image, compound="left", text="LOGIN TO CHAT ROOM", font="lucida 12 bold", background="sky blue")
        self.label1.grid(column=0, row=0, padx=30, pady=30)

        self.label2 = ttk.Label(self.tab1, text="Username: ")
        self.label2.grid(column=0, row=1, padx=30, pady=10)

        self.entry2 = ttk.Entry(self.tab1, width=30)
        self.entry2.grid(column=1, row=1, padx=10, pady=10)

        self.label3 = ttk.Label(self.tab1, text="Password: ")
        self.label3.grid(column=0, row=2, padx=30, pady=10)

        self.entry3 = ttk.Entry(self.tab1, width=30, show="*")
        self.entry3.grid(column=1, row=2, padx=10, pady=10)

        self.button1 = ttk.Button(self.tab1, text="login", cursor="hand2", width=10, command=self.login)
        self.button1.grid(column=0, row=3, padx=10, pady=30)

        # ------------------ sign-up Tab ----------------------

        self.label4 = ttk.Label(self.tab2, image=self.sign_up_image, compound="left", text="SIGN UP TO CHAT ROOM", background="sky blue", font="lucida 12 bold")
        self.label4.grid(column=0, row=0, padx=30, pady=30)

        self.label5 = ttk.Label(self.tab2, text="Username: ")
        self.label5.grid(column=0, row=1, padx=30, pady=10)

        self.entry5 = ttk.Entry(self.tab2, width=30)
        self.entry5.grid(column=1, row=1, padx=10, pady=10)

        self.label6 = ttk.Label(self.tab2, text="Mail ID: ")
        self.label6.grid(column=0, row=2, padx=30, pady=10)

        self.entry6 = ttk.Entry(self.tab2, width=30)
        self.entry6.grid(column=1, row=2, padx=10, pady=10)

        self.label7 = ttk.Label(self.tab2, text="Password: ")
        self.label7.grid(column=0, row=3, padx=30, pady=10)

        self.entry7 = ttk.Entry(self.tab2, width=30, show="*")
        self.entry7.grid(column=1, row=3, padx=10, pady=10)

        self.button2 = ttk.Button(self.tab2, text="Sign Up", cursor="hand2", width=10, command=self.sign_up)
        self.button2.grid(column=0, row=4, padx=10, pady=30)

        # flags
        self.gui_done = False
        self.running = True

    # Login function 
    def login(self):
        global UserName
        global Password
        UserName = self.entry2.get()
        Password = self.entry3.get()

        print(UserName)
        print(Password)

        self.sock.send('Login'.encode('ascii'))

        receive_thread = threading.Thread(target=self.receive)
        receive_thread.start()

    # sign-up function
    def sign_up(self):
        receive_thread = threading.Thread(target=self.receive)
        receive_thread.start()

        global UserName
        global mail_id
        global Password
        UserName = self.entry5.get()
        mail_id = self.entry6.get()
        Password = self.entry7.get()

        print(UserName)
        print(mail_id)
        print(Password)

        # Hashing the password using SHA-256
        sha256_hash = hashlib.sha256(Password.encode('utf-8')).hexdigest()

        # Send the hashed password to the server instead of the plain one
        self.sock.send('signup'.encode('ascii'))
        self.sock.send(sha256_hash.encode('utf-8'))  # send SHA-256 hashed password

    # Main chat window
    def openNewWindow(self):
        self.withdraw()

        mainChat = Toplevel()
        mainChat.geometry("900x650")
        mainChat.configure(bg="lightgray")

        mainChat.background1 = Image.open("images/10.jpg")
        mainChat.background1 = mainChat.background1.resize((900, 650), Image.LANCZOS)
        mainChat.background1 = ImageTk.PhotoImage(mainChat.background1)

        mainChat.bgLabel3 = tkinter.Label(mainChat, image=mainChat.background1)
        mainChat.bgLabel3.place(x=0, y=0)

        mainChat_label = tkinter.Label(mainChat, text="Welcome" + " : " + UserName, bg="lightgray")
        mainChat_label.config(font=("Arial", 12))
        mainChat_label.grid(padx=20, pady=5, row=0, column=0, columnspan=5)

        mainChat_label = tkinter.Label(mainChat, text="Chat:", bg="lightgray")
        mainChat_label.config(font=("Arial", 12))
        mainChat_label.grid(padx=20, pady=5, row=1, column=0, columnspan=5)

        global mainText_area
        mainText_area = tkinter.scrolledtext.ScrolledText(mainChat)
        mainText_area.grid(padx=10, pady=5, row=2, column=0, columnspan=4, rowspan=6)
        mainText_area.config(state='disabled')

        active_button = tkinter.Button(mainChat, text="Active Users", cursor="hand2", command=self.ask)
        active_button.config(font=("Arial", 12))
        active_button.grid(padx=20, pady=5, row=2, column=4)

        global user_area
        user_area = tkinter.Listbox(mainChat)
        user_area.grid(padx=20, pady=5, row=3, column=4, rowspan=5)

        msg_label = tkinter.Label(mainChat, text="Message:", bg="lightgray")
        msg_label.config(font=("Arial", 12))
        msg_label.grid(padx=20, pady=5, row=8, column=0, columnspan=5)

        global input_area
        input_area = tkinter.Text(mainChat, height=3)
        input_area.grid(padx=20, pady=5, row=9, column=0, columnspan=5)

        send_button = tkinter.Button(mainChat, text="Send", cursor="hand2", command=self.write)
        send_button.config(font=("Arial", 12))
        send_button.grid(padx=20, pady=5, row=10, column=0, columnspan=5)

        self.gui_done = True

    def stop(self):
        """ This method will be called when the window is closed. """
        self.running = False
        self.destroy()  # Close the window
        self.sock.close()  # Close the socket connection
        exit(0)  # Exit the application

    def write(self):
        message = f"{UserName}: {input_area.get('1.0', 'end')}"
        self.sock.send(message.encode('ascii'))
        input_area.delete('1.0', 'end')

    def ask(self):
        self.sock.send('GIVE'.encode('ascii'))

    def receive(self):
        while self.running:
            try:
                message = self.sock.recv(1024).decode('ascii')
                if message == 'NICK':
                    self.sock.send(UserName.encode('ascii'))
                elif message == 'PASS':
                    self.sock.send(Password.encode('ascii'))
                elif message == 'EMAIL':
                    self.sock.send(mail_id.encode('ascii'))
                elif message == 'Login Success':
                    print(message)
                    self.openNewWindow()
                elif message == 'Wrong INFO':
                    messagebox.showinfo(title="Error!", message="You have entered either wrong username or password. Please exit and try again.")
                    print(message)
                elif message == 'success':
                    print(message)
                    self.openNewWindow()
                    messagebox.showinfo(title="Welcome to Chat room", message="You Have been registered, enjoy your chatting😉")
                elif 'User' in message:
                    print(message)
                    user_area.insert(END, message)
                else:
                    if self.gui_done:
                        mainText_area.config(state='normal')
                        mainText_area.insert('end', message)
                        mainText_area.yview('end')
                        mainText_area.config(state='disabled')

            except ConnectionAbortedError:
                break      
            except Exception as e:
                print("An error occurred!")
                print(e)
                self.sock.close()
                break

# ==================================================

if __name__ == '__main__':
    app = App()
    app.mainloop()

# ==================================================
