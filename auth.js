(() => {
  const $ = (id) => document.getElementById(id);
  const form = $('registerForm') || $('loginForm');
  if (!form) return;
  const msg = $('msg');
  const button = form.querySelector('button[type="submit"]');
  const notice = $('redirectNotice');

  document.querySelectorAll('.toggle[data-target]').forEach((toggle) => {
    toggle.addEventListener('click', () => {
      const field = $(toggle.dataset.target);
      if (!field) return;
      const show = field.type === 'password';
      field.type = show ? 'text' : 'password';
      toggle.textContent = show ? 'Скрыть' : 'Показать';
    });
  });

  function showMessage(text, success=false) {
    msg.textContent = text;
    msg.style.color = success ? '#67d6a2' : '#ffb2a9';
  }
  async function request(path, body) {
    const response = await fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(body)
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.message || `Ошибка сервера (${response.status})`);
    return data;
  }
  function finish() {
    if (button) { button.disabled = true; button.textContent = 'Готово ✓'; }
    if (notice) notice.classList.add('show');
    showMessage('Успешно! Переводим на главный сайт…', true);
    setTimeout(() => { location.href = 'RedWeb.html'; }, 1400);
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (button) { button.disabled = true; button.textContent = 'Подожди…'; }
    showMessage('');
    try {
      if ($('registerForm')) {
        const name = $('name').value.trim();
        const email = $('email').value.trim();
        const password = $('password').value;
        if (name.length < 2 || name.length > 24) throw new Error('Никнейм должен содержать от 2 до 24 символов.');
        if (password.length < 8) throw new Error('Пароль должен быть не короче 8 символов.');
        await request('/api/register', {name, email, password});
      } else {
        const email = $('email').value.trim();
        const password = $('password').value;
        await request('/api/login', {email, password});
      }
      finish();
    } catch (error) {
      showMessage('Не получилось: ' + (error.message || 'Проверь подключение к серверу.'));
      if (button) { button.disabled = false; button.textContent = $('registerForm') ? 'Создать аккаунт →' : 'Войти в аккаунт →'; }
    }
  });
})();