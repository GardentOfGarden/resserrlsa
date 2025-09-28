class EclipseAuth {
    constructor() {
        this.currentUser = null;
        this.apps = [];
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.checkAuth();
        this.loadApps();
    }

    setupEventListeners() {
        const modal = document.getElementById('addAppModal');
        const closeBtn = modal?.querySelector('.close');
        const addAppForm = document.getElementById('addAppForm');

        if (closeBtn) {
            closeBtn.addEventListener('click', () => this.hideModal('addAppModal'));
        }

        if (addAppForm) {
            addAppForm.addEventListener('submit', (e) => this.handleAddApp(e));
        }

        window.addEventListener('click', (e) => {
            if (e.target === modal) {
                this.hideModal('addAppModal');
            }
        });

        const tabButtons = document.querySelectorAll('.tab-btn');
        tabButtons.forEach(btn => {
            btn.addEventListener('click', () => this.switchTab(btn));
        });

        const logoutBtn = document.querySelector('.logout-btn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.logout();
            });
        }
    }

    checkAuth() {
        const token = localStorage.getItem('eclipse_token');
        if (token && window.location.pathname.includes('index.html')) {
            window.location.href = 'dashboard.html';
        } else if (!token && !window.location.pathname.includes('index.html')) {
            window.location.href = 'index.html';
        }
    }

    async loadApps() {
        try {
            const response = await this.apiCall('GET', 'apps');
            if (response.success) {
                this.apps = response.data;
                this.renderApps();
            }
        } catch (error) {
            console.error('Error loading apps:', error);
        }
    }

    renderApps() {
        const appsGrid = document.querySelector('.apps-grid');
        if (!appsGrid) return;

        appsGrid.innerHTML = this.apps.map(app => `
            <div class="app-card">
                <div class="app-header">
                    <h3>${app.name} v${app.version}</h3>
                    <span class="app-status ${app.status}">${app.status}</span>
                </div>
                <div class="app-info">
                    <div class="app-stat">
                        <span class="stat-label">Ключи</span>
                        <span class="stat-value">${app.keys_count || 0}</span>
                    </div>
                    <div class="app-stat">
                        <span class="stat-label">Online</span>
                        <span class="stat-value">${app.online_users || 0}</span>
                    </div>
                </div>
                <div class="app-actions">
                    <button class="btn-secondary" onclick="eclipse.manageKeys('${app.id}')">Управление ключами</button>
                    <button class="btn-primary" onclick="eclipse.getIntegrationCode('${app.id}')">Получить код</button>
                </div>
            </div>
        `).join('');
    }

    showModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.style.display = 'block';
        }
    }

    hideModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.style.display = 'none';
        }
    }

    async handleAddApp(e) {
        e.preventDefault();
        const formData = new FormData(e.target);
        const appData = {
            name: formData.get('appName') || document.getElementById('appName')?.value,
            version: formData.get('appVersion') || document.getElementById('appVersion')?.value
        };

        try {
            const response = await this.apiCall('POST', 'apps', appData);
            if (response.success) {
                this.hideModal('addAppModal');
                this.loadApps();
                e.target.reset();
            } else {
                alert('Ошибка: ' + response.message);
            }
        } catch (error) {
            console.error('Error adding app:', error);
            alert('Ошибка при создании приложения');
        }
    }

    switchTab(button) {
        const tabButtons = button.parentElement.querySelectorAll('.tab-btn');
        const tabPanes = button.closest('.code-tabs').querySelectorAll('.tab-pane');
        const targetTab = button.dataset.tab;

        tabButtons.forEach(btn => btn.classList.remove('active'));
        tabPanes.forEach(pane => pane.classList.remove('active'));

        button.classList.add('active');
        document.getElementById(targetTab)?.classList.add('active');
    }

    async manageKeys(appId) {
        window.location.href = `keys.html?app=${appId}`;
    }

    async getIntegrationCode(appId) {
        const app = this.apps.find(a => a.id === appId);
        if (!app) return;

        const codeExamples = {
            cpp: `#include "eclipse.h"

std::string name = "${app.name}";
std::string ownerid = "${this.currentUser?.id || 'user_id'}";
std::string version = "${app.version}";
std::string url = "${window.location.origin}/api/";

Eclipse eclipse(name, ownerid, version, url);

if(eclipse.init()) {
    std::string key;
    std::cout << "Введите лицензионный ключ: ";
    std::cin >> key;
    
    if(eclipse.login(key)) {
        std::cout << "Успешная авторизация!" << std::endl;
    }
}`,
            python: `from eclipse import Eclipse

name = "${app.name}"
ownerid = "${this.currentUser?.id || 'user_id'}"
version = "${app.version}"
url = "${window.location.origin}/api/"

eclipse = Eclipse(name, ownerid, version, url)

if eclipse.init():
    key = input("Введите лицензионный ключ: ")
    if eclipse.login(key):
        print("Успешная авторизация!")`,
            java: `import com.eclipse.Eclipse;

public class Main {
    public static void main(String[] args) {
        String name = "${app.name}";
        String ownerid = "${this.currentUser?.id || 'user_id'}";
        String version = "${app.version}";
        String url = "${window.location.origin}/api/";
        
        Eclipse eclipse = new Eclipse(name, ownerid, version, url);
        
        if(eclipse.init()) {
            String key = System.console().readLine("Введите лицензионный ключ: ");
            if(eclipse.login(key)) {
                System.out.println("Успешная авторизация!");
            }
        }
    }
}`
        };

        this.showCodeModal(codeExamples);
    }

    showCodeModal(codes) {
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.style.display = 'block';
        modal.innerHTML = `
            <div class="modal-content" style="max-width: 800px;">
                <div class="modal-header">
                    <h3>Код для интеграции</h3>
                    <span class="close">&times;</span>
                </div>
                <div class="modal-body">
                    <div class="tab-buttons">
                        <button class="tab-btn active" data-tab="cpp-code">C++</button>
                        <button class="tab-btn" data-tab="python-code">Python</button>
                        <button class="tab-btn" data-tab="java-code">Java</button>
                    </div>
                    <div class="tab-content">
                        <div class="tab-pane active" id="cpp-code">
                            <pre><code>${codes.cpp}</code></pre>
                        </div>
                        <div class="tab-pane" id="python-code">
                            <pre><code>${codes.python}</code></pre>
                        </div>
                        <div class="tab-pane" id="java-code">
                            <pre><code>${codes.java}</code></pre>
                        </div>
                    </div>
                </div>
            </div>
        `;

        modal.querySelector('.close').addEventListener('click', () => {
            document.body.removeChild(modal);
        });

        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                document.body.removeChild(modal);
            }
        });

        const tabButtons = modal.querySelectorAll('.tab-btn');
        tabButtons.forEach(btn => {
            btn.addEventListener('click', () => this.switchTab(btn));
        });

        document.body.appendChild(modal);
    }

    async apiCall(method, endpoint, data = null) {
        const token = localStorage.getItem('eclipse_token');
        const headers = {
            'Content-Type': 'application/json',
        };

        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        const config = {
            method,
            headers,
        };

        if (data && method !== 'GET') {
            config.body = JSON.stringify(data);
        }

        try {
            const response = await fetch(`/api/${endpoint}`, config);
            return await response.json();
        } catch (error) {
            console.error('API call failed:', error);
            throw error;
        }
    }

    logout() {
        localStorage.removeItem('eclipse_token');
        window.location.href = 'index.html';
    }
}

function showAddAppModal() {
    eclipse.showModal('addAppModal');
}

const eclipse = new EclipseAuth();
