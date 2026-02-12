const tauriApi = window.__TAURI__ && window.__TAURI__.tauri;
const invoke = tauriApi ? tauriApi.invoke : null;

const listEl = document.getElementById("router-list");
const form = document.getElementById("router-form");
const statusEl = document.getElementById("status");
const deleteBtn = document.getElementById("delete-btn");
const addBtn = document.getElementById("add-btn");

let routers = [];
let selected = null;

function setStatus(text, isError = false) {
  statusEl.textContent = text;
  statusEl.style.color = isError ? "#f05b5b" : "#98a3b3";
}

function clearForm() {
  form.reset();
  selected = null;
  deleteBtn.disabled = true;
  setStatus("");
}

function fillForm(router) {
  form.name.value = router.name || "";
  form.address.value = router.address || "";
  form.login.value = router.login || "";
  form.password.value = "";
  deleteBtn.disabled = false;
}

function renderList() {
  listEl.innerHTML = "";
  routers.forEach((router) => {
    const li = document.createElement("li");
    li.textContent = `${router.name} — ${router.address}`;
    if (selected && selected.name === router.name) {
      li.classList.add("active");
    }
    li.onclick = () => {
      selected = router;
      fillForm(router);
      renderList();
    };
    listEl.appendChild(li);
  });
}

async function loadRouters() {
  if (!invoke) {
    setStatus("Tauri API unavailable", true);
    return;
  }
  routers = await invoke("list_routers");
  renderList();
  if (!selected && routers.length) {
    selected = routers[0];
    fillForm(selected);
    renderList();
  }
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!invoke) {
    setStatus("Tauri API unavailable", true);
    return;
  }
  setStatus("Saving...");
  const payload = {
    name: form.name.value.trim(),
    address: form.address.value.trim(),
    login: form.login.value.trim(),
    password: form.password.value,
    original_name: selected ? selected.name : null,
  };
  try {
    await invoke("save_router", { payload });
    setStatus("Saved");
    selected = null;
    await loadRouters();
    await invoke("refresh_tray_cmd");
  } catch (err) {
    setStatus(err, true);
  }
});

deleteBtn.addEventListener("click", async () => {
  if (!selected) return;
  if (!invoke) {
    setStatus("Tauri API unavailable", true);
    return;
  }
  setStatus("Deleting...");
  try {
    await invoke("delete_router", { name: selected.name });
    selected = null;
    await loadRouters();
    await invoke("refresh_tray_cmd");
    setStatus("Deleted");
  } catch (err) {
    setStatus(err, true);
  }
});

addBtn.addEventListener("click", () => {
  clearForm();
});

loadRouters();
