import os
import sqlite3
import hashlib
import requests
import tempfile
import shutil
import zipfile
import io
import json
from flask import Flask, request, jsonify, render_template
from yandex_cloud_ml_sdk import YCloudML
from dotenv import load_dotenv
import os


app = Flask(__name__)
DATABASE = 'analysis_results.db'
load_dotenv()


def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
                     CREATE TABLE IF NOT EXISTS results
                     (
                         id
                         INTEGER
                         PRIMARY
                         KEY
                         AUTOINCREMENT,
                         code_hash
                         TEXT
                         UNIQUE
                         NOT
                         NULL,
                         category
                         TEXT
                         NOT
                         NULL,
                         dangerous_lines
                         TEXT,
                         code_text
                         TEXT
                     )
                     ''')
        conn.commit()


init_db()


def hash_code(code):
    return hashlib.sha256(code.encode('utf-8')).hexdigest()


def add_result(code_hash, category, dangerous_lines=None, code_text=None):
    try:
        with sqlite3.connect(DATABASE) as conn:
            conn.execute(
                'INSERT INTO results (code_hash, category, dangerous_lines, code_text) VALUES (?, ?, ?, ?)',
                (code_hash, category, json.dumps(dangerous_lines) if dangerous_lines else None, code_text)
            )
            conn.commit()
    except sqlite3.IntegrityError:
        pass


def get_statistics():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT category, COUNT(*) FROM results GROUP BY category')
        return cursor.fetchall()


def get_repo_info(github_url):
    try:
        if 'github.com' not in github_url:
            raise ValueError("Некорректный URL GitHub репозитория")

        api_url = github_url.replace('https://github.com/', 'https://api.github.com/repos/')
        if api_url.endswith('/'):
            api_url = api_url[:-1]

        headers = {
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'application/vnd.github.v3+json'
        }
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()

        repo_data = response.json()
        return {
            'description': repo_data.get('description', 'Описание отсутствует'),
            'language': repo_data.get('language', 'Не указан'),
            'stars': repo_data.get('stargazers_count', 0),
            'forks': repo_data.get('forks_count', 0)
        }
    except Exception as e:
        print(f"Ошибка при получении информации о репозитории: {str(e)}")
        return None


def analyze_repo_description(repo_info):
    if not repo_info or not repo_info.get('description'):
        return "Не удалось получить описание репозитория"

    prompt = f"""
    Проанализируй описание GitHub репозитория и кратко охарактеризуй его назначение и функциональность.
    Описание: {repo_info['description']}
    Основной язык: {repo_info['language']}

    Ответ должен быть кратким (1-2 предложения) и содержать только суть проекта.
    """

    try:
        result = model.run([{"role": "user", "text": prompt}])
        return result.alternatives[0].text.strip('```').strip()
    except Exception as e:
        print(f"Ошибка при анализе описания: {str(e)}")
        return "Не удалось проанализировать описание репозитория"


def download_repo(github_url):
    if github_url.startswith('github.com'):
        github_url = 'https://' + github_url
    if not github_url.startswith(('https://github.com', 'http://github.com')):
        raise ValueError("Некорректный URL GitHub репозитория")

    github_url = github_url.rstrip('/')
    if github_url.endswith('.git'):
        github_url = github_url[:-4]

    temp_dir = tempfile.mkdtemp()
    repo_name = github_url.split('/')[-1]
    zip_url = f"{github_url}/archive/master.zip"

    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(zip_url, headers=headers)
        response.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(response.content)) as zip_ref:
            zip_ref.extractall(temp_dir)
        if os.path.exists(os.path.join(temp_dir, f"{repo_name}-master")):
            return os.path.join(temp_dir, f"{repo_name}-master")
        else:
            return os.path.join(temp_dir, f"{repo_name}-main")
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise ValueError(f"Ошибка при загрузке репозитория: {str(e)}")


def analyze_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        code = f.read()
    return analyze_code(code)


def analyze_code(code):
    code_hash = hash_code(code)

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT category, dangerous_lines FROM results WHERE code_hash = ?', (code_hash,))
        existing_result = cursor.fetchone()

    if existing_result:
        return {
            "category": existing_result[0],
            "dangerous_lines": json.loads(existing_result[1]) if existing_result[1] else []
        }

    result = model.run([
        {
            "role": "system",
            "text": """Ты эксперт по кибербезопасности. Проанализируй предоставленный код и:
1. Определи категорию угрозы
2. Найди все опасные участки кода
3. Верни ответ в JSON формате:

{
    "category": "название категории",
    "dangerous_lines": [
        {
            "line_number": номер строки,
            "code": "опасный код",
            "reason": "описание угрозы"
        }
    ]
}

Категории угроз:
- Безопасный код
- Потенциально нежелательные приложения (PUA)
- Фишинг
- Эксфильтрация данных
- Эксфильтрация PII
- Бэкдор
- Майнер / Похититель криптовалюты
- Другие вредоносные пакеты

Для каждого опасного участка укажи:
- ТОЧНЫЙ НОМЕР СТРОКИ УЧИТЫВАЯ ПУСТЫЕ СТРОКИ КАК ОТДЕЛЬНЫЕ
- Код этой строки
- Четкое объяснение, почему это опасно"""
        },
        {
            "role": "user",
            "text": code,
        }
    ])

    try:
        analysis_result = json.loads(result.alternatives[0].text.strip('```').replace('json\n', '').strip())

        valid_categories = [
            "Безопасный код",
            "Потенциально нежелательные приложения (PUA)",
            "Фишинг",
            "Эксфильтрация данных",
            "Эксфильтрация PII",
            "Бэкдор",
            "Майнер / Похититель криптовалюты",
            "Другие вредоносные пакеты"
        ]

        if analysis_result["category"] not in valid_categories:
            raise ValueError("Недопустимая категория угрозы")

        if analysis_result["category"] != "Безопасный код" and not analysis_result.get("dangerous_lines"):
            raise ValueError("Для вредоносного кода должны быть указаны опасные участки")

        add_result(
            code_hash=code_hash,
            category=analysis_result["category"],
            dangerous_lines=analysis_result["dangerous_lines"],
            code_text=code
        )

        return analysis_result

    except Exception as e:
        print(f"Ошибка анализа кода: {str(e)}")
        return {
            "category": "Ошибка анализа",
            "dangerous_lines": [{
                "line_number": 0,
                "code": "",
                "reason": f"Не удалось проанализировать код: {str(e)}"
            }]
        }


sdk = YCloudML(
    folder_id="b1gdpapc4lek06e0s7vi",
    auth=os.getenv("SECRET_KEY")
)

model = sdk.models.completions("yandexgpt", model_version="rc")
model = model.configure(temperature=0.3)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()

    if 'github_url' in data and data['github_url']:
        try:
            repo_info = get_repo_info(data['github_url'])
            repo_analysis = analyze_repo_description(
                repo_info) if repo_info else "Не удалось получить информацию о репозитории"

            repo_path = download_repo(data['github_url'])
            results = []

            for root, dirs, files in os.walk(repo_path):
                for file in files:
                    if file.endswith(('.py', '.js', '.java', '.c', '.cpp', '.go', '.php', '.rb', '.ts')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                code = f.read()
                                result = analyze_code(code)
                                results.append({
                                    'file': os.path.relpath(file_path, repo_path),
                                    'result': result['category'],
                                    'dangerous_lines': result['dangerous_lines'],
                                    'full_code': code.split('\n')
                                })
                        except Exception as e:
                            print(f"Error analyzing {file_path}: {str(e)}")
                            results.append({
                                'file': os.path.relpath(file_path, repo_path),
                                'result': f"Ошибка анализа: {str(e)}",
                                'dangerous_lines': [],
                                'full_code': []
                            })

            shutil.rmtree(repo_path, ignore_errors=True)
            return jsonify({
                "repo_analysis": repo_analysis,
                "repo_info": repo_info,
                "code_analysis": f"Анализ завершен. Проанализировано файлов: {len(results)}",
                "details": results
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    elif 'code' in data and data['code']:
        try:
            result = analyze_code(data['code'])
            return jsonify({
                "analysis": result['category'],
                "dangerous_lines": result['dangerous_lines'],
                "full_code": data['code'].split('\n')
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    return jsonify({"error": "Необходимо предоставить либо код, либо ссылку на GitHub"}), 400


@app.route('/get_chart_data')
def get_chart_data():
    statistics = get_statistics()
    labels = [row[0] for row in statistics]
    values = [row[1] for row in statistics]
    return jsonify({"labels": labels, "values": values})


if __name__ == '__main__':
    app.run(debug=True)