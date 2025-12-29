import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
import os

def process_images():
    # 1. ファイル選択ダイアログを開く
    file_paths = filedialog.askopenfilenames(
        title="128x128にしたい画像を選んでください（複数選択可）",
        filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.bmp;*.webp")]
    )
    
    if not file_paths:
        return

    count = 0
    error_count = 0
    
    # 2. 選ばれた画像を順番に処理
    for file_path in file_paths:
        try:
            img = Image.open(file_path)
            
            # 強制的に128x128にリサイズ
            img_resized = img.resize((128, 128), Image.Resampling.LANCZOS)
            
            # 保存ファイル名を作成（元の名前_128.png）
            file_dir, file_name = os.path.split(file_path)
            name, ext = os.path.splitext(file_name)
            save_path = os.path.join(file_dir, f"{name}_128.png")
            
            # 保存
            img_resized.save(save_path, "PNG")
            count += 1
            
        except Exception as e:
            print(f"エラー: {e}")
            error_count += 1

    # 3. 完了メッセージを表示
    if count > 0:
        messagebox.showinfo("完了", f"{count} 枚の画像を変換しました！\n元のフォルダに「_128」が付いた画像ができています。")
    elif error_count > 0:
        messagebox.showerror("エラー", "画像の変換に失敗しました。")

# --- アプリの画面を作る部分 ---
root = tk.Tk()
root.title("128px Converter")
root.geometry("300x150")

# 説明ラベル
label = tk.Label(root, text="下のボタンを押して\n変換したい画像を選んでください", pady=20)
label.pack()

# 実行ボタン
btn = tk.Button(root, text="画像を選択して変換", command=process_images, bg="#dddddd", padx=10, pady=5)
btn.pack()

# アプリを動かし続ける
root.mainloop()