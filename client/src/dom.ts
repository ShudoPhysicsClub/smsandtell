export function styleInputBase(el: HTMLInputElement | HTMLTextAreaElement): void {
  el.style.width = '100%';
  el.style.boxSizing = 'border-box';
  el.style.border = '1px solid #e2e6f3';
  el.style.borderRadius = '12px';
  el.style.padding = '10px 12px';
  el.style.background = '#f9fafb';
  el.style.color = '#1f2230';
  el.style.outline = 'none';
  el.style.transition = 'border-color 0.15s';
}

export function createRow(labelText: string, input: HTMLElement): HTMLDivElement {
  const row = document.createElement('div');
  row.style.marginBottom = '10px';

  const label = document.createElement('label');
  label.textContent = labelText;
  label.style.display = 'block';
  label.style.marginBottom = '6px';
  label.style.fontSize = '12px';
  label.style.fontWeight = '700';
  label.style.color = '#4a4f63';

  row.appendChild(label);
  row.appendChild(input);
  return row;
}

export function createInput(id: string, placeholder = '', value = ''): HTMLInputElement {
  const input = document.createElement('input');
  input.id = id;
  input.placeholder = placeholder;
  input.value = value;
  styleInputBase(input);
  return input;
}

export function createButton(id: string, text: string): HTMLButtonElement {
  const button = document.createElement('button');
  button.id = id;
  button.textContent = text;
  button.style.marginRight = '8px';
  button.style.marginBottom = '8px';
  button.style.padding = '10px 14px';
  button.style.border = 'none';
  button.style.borderRadius = '12px';
  button.style.background = '#6c63ff';
  button.style.color = '#ffffff';
  button.style.cursor = 'pointer';
  button.style.fontWeight = '700';
  button.style.fontSize = '13px';
  return button;
}

export function createSection(titleText: string): HTMLElement {
  const section = document.createElement('section');
  section.style.marginBottom = '14px';
  section.style.background = '#ffffff';
  section.style.border = '1px solid #e3e6ef';
  section.style.borderRadius = '14px';
  section.style.padding = '14px';

  const title = document.createElement('h3');
  title.textContent = titleText;
  title.style.margin = '0 0 10px 0';
  title.style.fontSize = '16px';
  title.style.color = '#25304a';

  section.appendChild(title);
  return section;
}

export function toErrorText(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
