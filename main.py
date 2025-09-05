import os
import http.server
import socketserver
import socket
import urllib.parse
import html
import time
from datetime import datetime
import argparse
import shutil
from functools import partial
from io import BytesIO
import json
import qrcode
import base64
import bcrypt
import secrets
import logging
import threading
import re
import hashlib

# Настройка логирования
logging.basicConfig(
    filename='server.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Парсинг аргументов командной строки
parser = argparse.ArgumentParser(description='PocketPyFile - HTTP File Server')
parser.add_argument('-p', '--port', type=int, default=8080, help='Server port')
parser.add_argument('-r', '--root', type=str, default=os.path.expanduser("~/storage/shared"),
                    help='Root directory')
parser.add_argument('--auth', action='store_true', help='Enable password authentication')
parser.add_argument('--user', type=str, default='admin', help='Username for authentication')
parser.add_argument('--pass', type=str, dest='password', default=None, help='Password for authentication')
parser.add_argument('--tokens', action='store_true', help='Enable token-based sharing')
parser.add_argument('--token-duration', type=int, default=86400,
                    help='Token validity duration in seconds (default: 24 hours)')
args = parser.parse_args()

PORT = args.port
DIRECTORY = os.path.expanduser(args.root)
SERVER_START_TIME = datetime.now()
AUTH_ENABLED = args.auth
USERNAME = args.user
PASSWORD = args.password
TOKENS_ENABLED = args.tokens
TOKEN_DURATION = args.token_duration
TOKENS = {}
STATIC_DIR = os.path.join(DIRECTORY, 'static')
ICONS_JSON = os.path.join(STATIC_DIR, 'icons.json')

# Проверка и создание директорий
if not os.path.exists(DIRECTORY):
    DIRECTORY = os.path.expanduser("~")
    logging.warning(f"Root directory changed to {DIRECTORY}")
os.makedirs(STATIC_DIR, exist_ok=True)

# Хеширование пароля
if AUTH_ENABLED and not PASSWORD:
    PASSWORD = secrets.token_urlsafe(8)
    logging.info(f"Generated password for user {USERNAME}")
if AUTH_ENABLED:
    PASSWORD_HASH = bcrypt.hashpw(PASSWORD.encode('utf-8'), bcrypt.gensalt())
else:
    PASSWORD_HASH = None

# Очистка просроченных токенов
def clean_expired_tokens():
    while True:
        now = time.time()
        expired = [t for t, data in TOKENS.items() if data['expiry'] <= now]
        for t in expired:
            del TOKENS[t]
            logging.info(f"Removed expired sharing token: {t}")
        time.sleep(3600)

if TOKENS_ENABLED:
    threading.Thread(target=clean_expired_tokens, daemon=True).start()

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="PocketPyFile"')
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()

    def check_auth(self):
        if not AUTH_ENABLED and not TOKENS_ENABLED:
            return True
        if TOKENS_ENABLED:
            parsed_url = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed_url.query)
            if 'token' in query:
                token = query['token'][0]
                if token in TOKENS and TOKENS[token]['expiry'] > time.time():
                    return True
            token = self.headers.get('X-Access-Token') or self.headers.get('Authorization', '').replace('Bearer ', '')
            if token in TOKENS and TOKENS[token]['expiry'] > time.time():
                requested_path = os.path.abspath(self.translate_path(self.path))
                token_path = os.path.abspath(TOKENS[token]['path'])
                if requested_path.startswith(token_path):
                    return True
        if AUTH_ENABLED:
            auth_header = self.headers.get('Authorization')
            if auth_header is None or not auth_header.startswith('Basic '):
                return False
            try:
                auth_decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
                username, password = auth_decoded.split(':', 1)
                if username == USERNAME and bcrypt.checkpw(password.encode('utf-8'), PASSWORD_HASH):
                    return True
            except:
                return False
        return False

    def validate_path(self, path):
        abs_path = os.path.abspath(path)
        if not abs_path.startswith(os.path.abspath(DIRECTORY)):
            logging.error(f"Path {abs_path} is outside root directory {DIRECTORY}")
            return False
        if os.path.islink(path) or '..' in path or re.search(r'[<>|*?"]', path):
            logging.error(f"Path {path} contains invalid components")
            return False
        return True

    def send_head(self):
        if TOKENS_ENABLED:
            parsed_url = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed_url.query)
            if 'token' in query:
                token = query['token'][0]
                if token in TOKENS and TOKENS[token]['expiry'] > time.time():
                    self.path = parsed_url.path
                    return super().send_head()
        if (AUTH_ENABLED or TOKENS_ENABLED) and not self.check_auth():
            self.do_AUTHHEAD()
            self.wfile.write(b'Authentication required')
            return None
        path = self.translate_path(self.path)
        if os.path.isdir(path):
            if not self.path.endswith('/'):
                self.send_response(301)
                self.send_header('Location', self.path + '/')
                self.end_headers()
                return None
            return self.list_directory(path)
        return super().send_head()

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', f'http://localhost:{PORT}')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, PUT, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Access-Token')
        self.send_header('Connection', 'keep-alive')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed_url.query)
        if 'toast' in query:
            self.path = parsed_url.path

        if self.path == '/_get_token':
            if not TOKENS_ENABLED:
                self.send_error(403, "Token sharing is not enabled")
                return
            if AUTH_ENABLED and not self.check_auth():
                self.do_AUTHHEAD()
                self.wfile.write(b'Authentication required')
                return
            path = self.translate_path("/")
            token = generate_token(path)
            response = {
                'token': token,
                'expires_in': TOKEN_DURATION,
                'path': path,
                'expires_at': time.time() + TOKEN_DURATION
            }
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))
            return

        path = self.translate_path(self.path)
        if os.path.isdir(path):
            # Directories are handled by send_head via list_directory
            self.send_head()
            return
        if os.path.isfile(path):
            try:
                logging.debug(f"Serving file: {path}")
                file_size = os.path.getsize(path)
                self.send_response(200)
                self.send_header('Content-type', self.guess_type(path))
                self.send_header('Content-Length', file_size)
                self.send_header('X-Download-Status', 'started')
                if self.path.endswith('/favicon.ico'):
                    self.send_header('Connection', 'close')
                    self.send_header('Cache-Control', 'public, max-age=604800')
                self.end_headers()
                with open(path, 'rb') as f:
                    try:
                        shutil.copyfileobj(f, self.wfile)
                        logging.info(f"Successfully downloaded file: {path} ({file_size} bytes)")
                    except BrokenPipeError:
                        logging.warning(f"Broken pipe while serving {path}")
                        return
            except Exception as e:
                logging.error(f"Error downloading file {path}: {str(e)}")
                self.send_error(500, f"Error downloading file: {str(e)}")
                return
        else:
            # Handle other cases (e.g., file not found) via send_head
            f = self.send_head()
            if f:
                try:
                    if isinstance(f, int):
                        # Handle file descriptor
                        with os.fdopen(f, 'rb') as file_obj:
                            shutil.copyfileobj(file_obj, self.wfile)
                    else:
                        # Handle file object
                        shutil.copyfileobj(f, self.wfile)
                        f.close()
                except Exception as e:
                    logging.error(f"Error serving file {path}: {str(e)}")
                    if not isinstance(f, int):
                        f.close()
                    self.send_error(500, str(e))
                return
            # If send_head returned None, headers were already sent
            return

    def do_POST(self):
        content_type = self.headers.get('Content-Type', '')
        request_type = self.headers.get('X-Request-Type', '')
        content_length = int(self.headers.get('Content-Length', 0))
        logging.debug(f"Content-Type: {content_type}, Content-Length: {content_length}, X-Request-Type: {request_type}")

        if self.path == '/_upload_icon':
            if not content_type.startswith('multipart/form-data'):
                logging.error("Invalid content type for icon upload, expected multipart/form-data")
                self.send_error(400, "Expected multipart/form-data")
                return
            try:
                boundary = content_type.split('boundary=')[1].encode()
                data = self.rfile.read(content_length)
                parts = data.split(b'--' + boundary)
                for part in parts:
                    if b'filename="' in part:
                        filename_match = re.search(b'filename="(.+?)"', part)
                        folder_path_match = re.search(b'name="folder_path"\r\n\r\n(.+?)\r\n', part)
                        if not filename_match or not folder_path_match:
                            logging.error("Missing filename or folder_path in icon upload")
                            self.send_error(400, "Missing filename or folder_path")
                            return
                        filename = filename_match.group(1).decode('utf-8', errors='ignore')
                        folder_path = folder_path_match.group(1).decode('utf-8', errors='ignore')
                        if not filename.lower().endswith(('.png', '.jpg', '.jpeg','.py')):
                            logging.error(f"Unsupported icon type: {filename}")
                            self.send_error(415, "Only PNG and JPG icons allowed")
                            return
                        try:
                            file_data = part.split(b'\r\n\r\n')[1].rsplit(b'\r\n', 1)[0]
                        except IndexError:
                            logging.error("Failed to parse icon data")
                            self.send_error(400, "Invalid multipart data")
                            return
                        icon_dir = os.path.join(STATIC_DIR, 'custom-icons')
                        os.makedirs(icon_dir, exist_ok=True)
                        icon_filename = f"{secrets.token_hex(8)}.{filename.split('.')[-1]}"
                        icon_path = os.path.join(icon_dir, icon_filename)
                        with open(icon_path, 'wb') as f:
                            f.write(file_data)
                        icons_map = {}
                        if os.path.exists(ICONS_JSON):
                            with open(ICONS_JSON, 'r') as f:
                                icons_map = json.load(f)
                        icons_map[folder_path] = f"/static/custom-icons/{icon_filename}"
                        with open(ICONS_JSON, 'w') as f:
                            json.dump(icons_map, f)
                        logging.info(f"Uploaded icon for folder {folder_path}: {icon_path}")
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(b'{"status": "success"}')
                        return
            except Exception as e:
                logging.error(f"Error uploading icon: {str(e)}")
                self.send_error(500, f"Error uploading icon: {str(e)}")
                return

        if self.path == '/_rename':
            if not content_type.startswith('application/json'):
                logging.error("Invalid content type for rename, expected application/json")
                self.send_error(400, "Expected JSON content type")
                return
            try:
                post_data = self.rfile.read(content_length).decode('utf-8')
                logging.debug(f"Received rename data: {post_data}")
                data = json.loads(post_data)
                old_path = data.get('old_path')
                new_name = data.get('new_name')
                if not old_path or not new_name or re.search(r'[<>|*?"/\\]', new_name):
                    logging.error(f"Invalid old_path: {old_path} or new_name: {new_name}")
                    self.send_error(400, "Invalid old_path or new_name")
                    return
                abs_old_path = self.translate_path(old_path)
                if not self.validate_path(abs_old_path):
                    logging.error(f"Invalid old path: {abs_old_path}")
                    self.send_error(403, "Invalid path")
                    return
                new_path = os.path.join(os.path.dirname(abs_old_path), new_name)
                if not self.validate_path(new_path):
                    logging.error(f"Invalid new path: {new_path}")
                    self.send_error(403, "Invalid new path")
                    return
                try:
                    os.rename(abs_old_path, new_path)
                    logging.info(f"Renamed {abs_old_path} to {new_path}")
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(b'{"status": "success"}')
                except PermissionError as e:
                    logging.error(f"Permission denied renaming {abs_old_path} to {new_path}: {str(e)}")
                    self.send_error(403, f"Permission denied: {str(e)}")
                except Exception as e:
                    logging.error(f"Error renaming {abs_old_path} to {new_path}: {str(e)}")
                    self.send_error(500, str(e))
            except json.JSONDecodeError as e:
                logging.error(f"Invalid JSON in rename request: {str(e)}")
                self.send_error(400, "Invalid JSON")
            return

        if content_type.startswith('application/x-www-form-urlencoded'):
            try:
                post_data = self.rfile.read(content_length).decode('utf-8')
                params = urllib.parse.parse_qs(post_data)
                folder_name = params.get('folder_name', [''])[0]
                if not folder_name or re.search(r'[<>|*?"/\\]', folder_name):
                    logging.error(f"Invalid folder name: {folder_name}")
                    self.send_error(400, "Invalid folder name")
                    return
                folder_path = os.path.join(self.translate_path(self.path), folder_name)
                if not self.validate_path(folder_path):
                    logging.error(f"Invalid folder path: {folder_path}")
                    self.send_error(403, "Invalid path")
                    return
                try:
                    os.makedirs(folder_path, exist_ok=True)
                    logging.info(f"Created folder: {folder_path}")
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(b'{"status": "success"}')
                except PermissionError as e:
                    logging.error(f"Permission denied creating folder {folder_path}: {str(e)}")
                    self.send_error(403, f"Permission denied: {str(e)}")
                except Exception as e:
                    logging.error(f"Error creating folder {folder_path}: {str(e)}")
                    self.send_error(500, str(e))
            except Exception as e:
                logging.error(f"Error processing folder creation: {str(e)}")
                self.send_error(500, f"Error processing folder creation: {str(e)}")
            return

        if content_type.startswith('multipart/form-data'):
            try:
                boundary = content_type.split('boundary=')[1].encode()
                data = self.rfile.read(content_length)
                parts = data.split(b'--' + boundary)
                uploaded_files = []
                for part in parts:
                    if b'filename="' in part:
                        filename_match = re.search(b'filename="(.+?)"', part)
                        if not filename_match:
                            logging.warning("No filename found in multipart part")
                            continue
                        filename = filename_match.group(1).decode('utf-8', errors='ignore')
                        if re.search(r'[<>|*?"/\\]', filename):
                            logging.error(f"Invalid filename: {filename}")
                            self.send_error(400, f"Invalid filename: {filename}")
                            return
                        try:
                            file_data = part.split(b'\r\n\r\n')[1].rsplit(b'\r\n', 1)[0]
                        except IndexError:
                            logging.error(f"Failed to parse file data for {filename}")
                            self.send_error(400, f"Invalid multipart data for {filename}")
                            return
                        file_size = len(file_data)
                        if file_size > 50 * 1024 * 1024:
                            logging.error(f"File too large: {filename} ({file_size} bytes)")
                            self.send_error(413, f"File too large: {filename}")
                            return
                        allowed_extensions = {'.txt', '.jpg', '.png', '.pdf', '.jpeg', '.gif', '.webp', '.mp3'}
                        if not any(filename.lower().endswith(ext) for ext in allowed_extensions):
                            logging.error(f"Unsupported file type: {filename}")
                            self.send_error(415, f"Unsupported file type: {filename}")
                            return
                        file_path = os.path.join(self.translate_path(self.path), filename)
                        if not self.validate_path(file_path):
                            logging.error(f"Invalid file path: {file_path}")
                            self.send_error(403, f"Invalid path: {file_path}")
                            return
                        with open(file_path, 'wb') as f:
                            f.write(file_data)
                        uploaded_files.append(filename)
                        logging.info(f"Uploaded file: {file_path}")
                if uploaded_files:
                    logging.info(f"Uploaded files: {', '.join(uploaded_files)}")
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(b'{"status": "success"}')
                else:
                    logging.error("No valid files uploaded")
                    self.send_error(400, "No valid files uploaded")
            except Exception as e:
                logging.error(f"Error processing multipart form-data: {str(e)}")
                self.send_error(500, f"Error processing upload: {str(e)}")
            return

        logging.error(f"Invalid POST request to {self.path}")
        self.send_error(400, "Invalid request")

    def do_DELETE(self):
        path = self.translate_path(self.path)
        logging.debug(f"Received DELETE request for {path}")
        if self.validate_path(path):
            try:
                if os.path.isdir(path):
                    icons_map = {}
                    if os.path.exists(ICONS_JSON):
                        with open(ICONS_JSON, 'r') as f:
                            icons_map = json.load(f)
                        if self.path in icons_map:
                            icon_path = os.path.join(DIRECTORY, icons_map[self.path].lstrip('/'))
                            if os.path.exists(icon_path):
                                os.remove(icon_path)
                            del icons_map[self.path]
                            with open(ICONS_JSON, 'w') as f:
                                json.dump(icons_map, f)
                            logging.info(f"Removed icon for deleted folder: {self.path}")
                    shutil.rmtree(path)
                else:
                    os.remove(path)
                logging.info(f"Deleted: {path}")
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"status": "success"}')
            except Exception as e:
                logging.error(f"Error deleting {path}: {str(e)}")
                self.send_error(500, str(e))
        else:
            logging.error(f"Invalid delete path: {path}")
            self.send_error(403, "Invalid path")

    def list_directory(self, path):
        try:
            items = os.listdir(path)
            items.sort(key=lambda a: a.lower())
            html_content = self.generate_html_index(path, items)
            etag = hashlib.md5(html_content.encode('utf-8')).hexdigest()
            if self.headers.get('If-None-Match') == etag:
                self.send_response(304)
                self.end_headers()
                return None
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html_content)))
            self.send_header("ETag", etag)
            self.end_headers()
            return self.wfile.write(html_content.encode('utf-8'))
        except PermissionError:
            logging.error(f"Permission denied listing directory: {path}")
            self.send_error_page(403, "No permission to list directory")
        except Exception as e:
            logging.error(f"Error listing directory {path}: {str(e)}")
            self.send_error_page(500, str(e))

    def generate_html_index(self, path, items):
        rel_path = os.path.relpath(path, DIRECTORY)
        if rel_path == ".":
            rel_path = ""
        current_dir = self.path.rstrip('/') or '/'

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PocketPyFile - {html.escape(rel_path)}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        body {{ padding: 20px; }}
        .file-icon {{ margin-right: 8px; }}
        .folder-link, .file-link {{ text-decoration: none; }}
        .folder-link:hover, .file-link:hover {{ text-decoration: underline; }}
        .table {{ margin-top: 20px; }}
        .toast-container {{
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1050;
        }}
    </style>
</head>
<body>
    <div class="toast-container"></div>
    <div class="container">
        <h2>PocketPyFile Demo by LakLadon</h2>
        <p>Current directory: <code>/{html.escape(rel_path)}</code></p>
        <form id="uploadForm" method="post" enctype="multipart/form-data" class="mb-3">
            <div class="input-group">
                <input type="file" class="form-control" name="file" multiple>
                <button class="btn btn-primary" type="submit">Upload</button>
            </div>
        </form>
        <form id="createFolderForm" method="post" class="mb-3">
            <div class="input-group">
                <input type="text" class="form-control" id="folderName" name="folder_name" placeholder="New folder name">
                <button class="btn btn-success" type="submit">Create Folder</button>
            </div>
        </form>
        <table class="table table-hover">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Size</th>
                    <th>Modified</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
        """
        if rel_path:
            parent_path = os.path.dirname(rel_path)
            if parent_path == ".":
                parent_path = ""
            # Ensure parent_path has a trailing slash
            parent_url = f"/{parent_path}/" if parent_path else "/"
            html_content += f"""
                <tr>
                    <td colspan="4">
                        <a href="{parent_url}" class="folder-link">
                            <i class="bi bi-arrow-left-circle file-icon"></i> Go up
                        </a>
                    </td>
                </tr>
            """
        icons_map = {}
        if os.path.exists(ICONS_JSON):
            with open(ICONS_JSON, 'r') as f:
                try:
                    icons_map = json.load(f)
                except:
                    logging.error(f"Failed to load {ICONS_JSON}")
        for name in items:
            if name.startswith('.'):
                continue
            full_path = os.path.join(path, name)
            if not os.path.exists(full_path):
                continue
            try:
                display_name = html.escape(name)
                is_dir = os.path.isdir(full_path)
                size = "-" if is_dir else os.path.getsize(full_path)
                mtime = datetime.fromtimestamp(os.path.getmtime(full_path)).strftime('%Y-%m-%d %H:%M:%S')
                item_path = f"{current_dir}/{urllib.parse.quote(name)}".replace('//', '/')
                icon = f'<img src="{icons_map.get(item_path, "")}" class="custom-icon" style="width: 24px; height: 24px; object-fit: contain;">' if is_dir and item_path in icons_map else '<i class="bi bi-folder-fill text-warning file-icon"></i>' if is_dir else '<i class="bi bi-file-earmark file-icon"></i>'
                # Ensure folder links have a trailing slash
                href = f"{urllib.parse.quote(name)}/" if is_dir else urllib.parse.quote(name)
                display_name = f'<a href="{href}" class="{"folder-link" if is_dir else "file-link"}">{display_name}{"/" if is_dir else ""}</a>'
                actions = f"""
                    <div class="btn-group btn-group-sm">
                        <button class="btn btn-outline-danger" onclick="deleteItem('{item_path}')">Delete</button>
                        <button class="btn btn-outline-primary" onclick="renameItem('{item_path}', '{html.escape(name)}')">Rename</button>
                        {'<button class="btn btn-outline-info" onclick="uploadIcon(\'' + item_path + '\')">Upload Icon</button>' if is_dir else ''}
                    </div>
                """
                html_content += f"""
                    <tr>
                        <td>{icon}{display_name}</td>
                        <td>{self.format_size(size)}</td>
                        <td>{mtime}</td>
                        <td>{actions}</td>
                    </tr>
                """
            except Exception as e:
                logging.error(f"Error processing {name}: {e}")
                continue
        toast_script = ""
        parsed_url = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed_url.query)
        if 'toast' in query:
            toast_message = query['toast'][0]
            toast_type = query.get('toast_type', ['success'])[0]
            toast_script = f"showToast('{toast_message}', '{toast_type}');"
        html_content += f"""
            </tbody>
        </table>
        <div class="modal fade" id="uploadIconModal" tabindex="-1" aria-labelledby="uploadIconModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="uploadIconModalLabel">Upload Folder Icon</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <form id="uploadIconForm" method="post" enctype="multipart/form-data">
                        <div class="modal-body">
                            <div class="mb-3">
                                <label for="iconFile" class="form-label">Choose Icon (PNG/JPG)</label>
                                <input type="file" class="form-control" id="iconFile" name="icon_file" accept=".png,.jpg,.jpeg" required>
                                <input type="hidden" id="folderPath" name="folder_path">
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                            <button type="submit" class="btn btn-primary">Upload</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            function showToast(message, type = 'success') {{
                const toastContainer = document.querySelector('.toast-container');
                const toast = document.createElement('div');
                toast.className = `toast align-items-center text-bg-${{type}} border-0`;
                toast.setAttribute('role', 'alert');
                toast.setAttribute('aria-live', 'assertive');
                toast.setAttribute('aria-atomic', 'true');
                toast.innerHTML = `
                    <div class="d-flex">
                        <div class="toast-body">${{message}}</div>
                        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
                    </div>
                `;
                toastContainer.appendChild(toast);
                const bsToast = new bootstrap.Toast(toast);
                bsToast.show();
                setTimeout(() => bsToast.hide(), 3000);
            }}

            {toast_script}

            function uploadIcon(path) {{
                document.getElementById('folderPath').value = path;
                const modal = new bootstrap.Modal(document.getElementById('uploadIconModal'));
                modal.show();
            }}

            document.getElementById('uploadIconForm').addEventListener('submit', function(e) {{
                e.preventDefault();
                const formData = new FormData(this);
                fetch('/_upload_icon', {{
                    method: 'POST',
                    body: formData
                }})
                .then(response => {{
                    if (response.ok) {{
                        showToast('Icon uploaded successfully!', 'success');
                        setTimeout(() => location.reload(), 1000);
                    }} else {{
                        response.text().then(text => {{
                            showToast('Error: ' + text, 'danger');
                        }});
                    }}
                }})
                .catch(error => {{
                    showToast('Request error: ' + error, 'danger');
                }});
            }});

            document.getElementById('uploadForm').addEventListener('submit', function(e) {{
                e.preventDefault();
                const files = this.querySelector('input[name="file"]').files;
                if (files.length === 0) {{
                    showToast('No files selected!', 'warning');
                    return;
                }}
                const formData = new FormData(this);
                fetch(window.location.pathname, {{
                    method: 'POST',
                    body: formData
                }})
                .then(response => {{
                    if (response.ok) {{
                        showToast('Files uploaded successfully!', 'success');
                        setTimeout(() => location.reload(), 1000);
                    }} else {{
                        response.text().then(text => {{
                            showToast('Error: ' + text, 'danger');
                        }});
                    }}
                }})
                .catch(error => {{
                    showToast('Request error: ' + error, 'danger');
                }});
            }});

            document.getElementById('createFolderForm').addEventListener('submit', function(e) {{
                e.preventDefault();
                const folderName = document.getElementById('folderName').value.trim();
                if (!folderName) {{
                    showToast('Folder name cannot be empty!', 'warning');
                    return;
                }}
                fetch(window.location.pathname, {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }},
                    body: `folder_name=${{encodeURIComponent(folderName)}}`
                }})
                .then(response => {{
                    if (response.ok) {{
                        showToast('Folder created successfully!', 'success');
                        setTimeout(() => location.reload(), 1000);
                    }} else {{
                        response.text().then(text => {{
                            showToast('Error: ' + text, 'danger');
                        }});
                    }}
                }})
                .catch(error => {{
                    showToast('Request error: ' + error, 'danger');
                }});
            }});

            function deleteItem(path) {{
                if (confirm('Are you sure you want to delete "' + decodeURIComponent(path.split('/').pop()) + '"?')) {{
                    fetch(path, {{ method: 'DELETE' }})
                        .then(response => {{
                            if (response.ok) {{
                                showToast('Deleted successfully!', 'success');
                                setTimeout(() => location.reload(), 1000);
                            }} else {{
                                response.text().then(text => {{
                                    showToast('Error: ' + text, 'danger');
                                }});
                            }}
                        }})
                        .catch(error => {{
                            showToast('Request error: ' + error, 'danger');
                        }});
                }}
            }}

            function renameItem(path, currentName) {{
                const newName = prompt('Enter new name:', currentName);
                if (newName && newName !== currentName) {{
                    fetch('/_rename', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{ old_path: path, new_name: newName }})
                    }})
                    .then(response => {{
                        if (response.ok) {{
                            showToast('Renamed successfully!', 'success');
                            setTimeout(() => location.reload(), 1000);
                        }} else {{
                            response.text().then(text => {{
                                showToast('Error: ' + text, 'danger');
                            }});
                        }}
                    }})
                    .catch(error => {{
                        showToast('Request error: ' + error, 'danger');
                    }});
                }}
            }}
        </script>
    </div>
</body>
</html>
        """
        return html_content

    def format_size(self, size):
        if size == "-":
            return size
        try:
            size = float(size)
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size < 1024.0:
                    return f"{size:.1f} {unit}"
                size /= 1024.0
            return f"{size:.1f} TB"
        except (ValueError, TypeError):
            return "N/A"

    def send_error_page(self, status_code, message=None, error_message=None):
        error_pages = {
            403: {
                "title": "Forbidden",
                "icon": "bi-lock-fill",
                "icon_class": "text-danger",
                "default_msg": "You don't have permission to access this resource."
            },
            404: {
                "title": "Not Found",
                "icon": "bi-exclamation-triangle-fill",
                "icon_class": "text-warning",
                "default_msg": "The requested resource was not found."
            },
            500: {
                "title": "Server Error",
                "icon": "bi-bug-fill",
                "icon_class": "text-danger",
                "default_msg": "Something went wrong on our server."
            }
        }
        error_info = error_pages.get(status_code, {
            "title": f"{status_code} Error",
            "icon": "bi-question-circle-fill",
            "icon_class": "text-info",
            "default_msg": "An error occurred."
        })
        error_details = f'<code>{html.escape(str(error_message))}</code>' if error_message else ''
        content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{status_code} - PocketPyFile</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        :root {{
            --bs-dark-bg: #1a1e21;
            --bs-dark-border: #2c3034;
            --bs-primary-text: #6ea8fe;
            --bs-danger: #dc3545;
            --bs-warning: #ffc107;
        }}
        body {{
            background-color: var(--bs-dark-bg);
            color: #f8f9fa;
            padding: 20px;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        }}
        .container {{
            max-width: 800px;
            margin: 50px auto;
            padding: 30px;
            background-color: var(--bs-dark-bg);
            border-radius: 8px;
            border: 1px solid var(--bs-dark-border);
        }}
        .error-icon {{
            font-size: 5rem;
            margin-bottom: 20px;
        }}
        .error-title {{
            font-size: 2.5rem;
            margin-bottom: 15px;
        }}
        .error-details {{
            background-color: rgba(0, 0, 0, 0.2);
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
            font-family: monospace;
            white-space: pre-wrap;
        }}
        .btn-home {{
            margin-top: 20px;
        }}
        .text-danger {{
            color: var(--bs-danger);
        }}
        .text-warning {{
            color: var(--bs-warning);
        }}
        .text-info {{
            color: var(--bs-primary-text);
        }}
    </style>
</head>
<body>
    <div class="container text-center">
        <div class="error-icon {error_info['icon_class']}">
            <i class="bi {error_info['icon']}"></i>
        </div>
        <h1 class="error-title">{status_code} - {error_info['title']}</h1>
        <p class="lead">{message or error_info['default_msg']}</p>
        {error_details}
        <a href="/" class="btn btn-primary btn-home">
            <i class="bi bi-house-door"></i> Return to Home
        </a>
        <footer class="mt-5 text-center text-muted">
            <p>PocketPyFile</p>
            <p class="small">{time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </footer>
    </div>
</body>
</html>
        """.encode('utf-8')
        self.send_response(status_code)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

def generate_token(path):
    if not TOKENS_ENABLED:
        return None
    token = secrets.token_urlsafe(32)
    expiry = time.time() + TOKEN_DURATION
    TOKENS[token] = {
        'path': os.path.abspath(path),
        'expiry': expiry
    }
    logging.info(f"Generated token for path: {path}")
    return token

def check_port(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) != 0

def run_server():
    os.chdir(DIRECTORY)
    for port in range(PORT, PORT + 10):
        if check_port(port):
            handler = partial(CustomHTTPRequestHandler)
            with socketserver.TCPServer(("", port), handler) as httpd:
                logging.info(f"Server started on port {port}")
                print(f"Server running on port {port}")
                print(f"Access at: http://localhost:{port}")
                print(f"Root directory: {DIRECTORY}")
                if AUTH_ENABLED:
                    print(f"Authentication enabled - Username: {USERNAME}")
                if TOKENS_ENABLED:
                    print(f"Token sharing enabled - Token duration: {TOKEN_DURATION} seconds")
                print("Press Ctrl+C to stop the server")
                httpd.serve_forever()
                break
        else:
            print(f"Port {port} is busy, trying next...")
    else:
        raise OSError("No available ports found")

if __name__ == "__main__":
    run_server()
