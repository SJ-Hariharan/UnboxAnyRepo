// Demo fixture: a counter rendered by a Vite app.
let count = 0;
const app = document.querySelector('#app');
const button = document.createElement('button');
button.textContent = 'Count: 0';
button.addEventListener('click', () => {
  count += 1;
  button.textContent = `Count: ${count}`;
});
app.append(button);
