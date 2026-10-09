'use strict';

// 请求历史视图（并入管理壳）：同源会话 Cookie 请求，元数据筛选 + 游标分页，
// 四阶段正文默认直接可见，安全文本渲染（不 innerHTML 注入模型输出）。
(() => {
  const stageInfo = [
    { stage: 'input', title: '传入原文', en: 'ORIGINAL INPUT' },
    { stage: 'redacted', title: '脱敏后的文本', en: 'REDACTED OUTBOUND' },
    { stage: 'upstream', title: '大模型返回的文本', en: 'MODEL RESPONSE' },
    { stage: 'restored', title: '还原后的文本', en: 'RESTORED OUTPUT' }
  ];
  const statusNames = { processing: '进行中', completed: '完成', blocked: '被阻断', failed: '失败', partial: '部分内容' };
  const state = { items: [], nextCursor: null, selected: null, detail: null, highlight: true, listLoading: true, detailLoading: false, listError: '', detailError: '', listLoaded: false, epoch: 0 };
  const filters = { model: '', protocol: '', status: '', error_code: '', created_after: '', created_before: '' };
  const dom = Object.fromEntries(['request-list', 'history-count', 'record-content', 'refresh-history', 'load-more', 'toast', 'selection-status', 'history-filters', 'filter-model', 'filter-protocol', 'filter-status', 'filter-error-code', 'filter-created-after', 'filter-created-before', 'filter-error', 'filter-reset'].map(id => [id, document.getElementById(id)]));
  let listController = null, detailController = null, listSequence = 0, detailSequence = 0, toastTimer = null;

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function icon(name) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('fill', 'none'); svg.setAttribute('aria-hidden', 'true'); svg.setAttribute('class', 'copy-icon');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('stroke', 'currentColor'); path.setAttribute('stroke-width', '1.3'); path.setAttribute('stroke-linecap', 'round'); path.setAttribute('stroke-linejoin', 'round');
    path.setAttribute('d', 'M8 8h12v13H8zM4 16V3h12v2');
    svg.append(path); return svg;
  }
  function restoreFocus(id) {
    const target = document.getElementById(id);
    if (target && target.isConnected && !target.disabled) target.focus({ preventScroll: true });
  }
  function announce(message) { dom['selection-status'].textContent = message; }
  function notify(message) {
    dom.toast.textContent = message; dom.toast.classList.add('visible'); clearTimeout(toastTimer);
    toastTimer = setTimeout(() => dom.toast.classList.remove('visible'), 4000);
  }
  function formatTime(value, dateOnly = false) {
    if (typeof value !== 'string') return '时间未提供';
    const date = new Date(value);
    if (!Number.isFinite(date.getTime())) return value;
    return new Intl.DateTimeFormat('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', ...(dateOnly ? {} : { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) }).format(date);
  }
  function shortId(value) { return String(value).slice(0, 8); }
  function recordName(record) { return typeof record.model === 'string' && record.model ? record.model : '模型未提供'; }
  function badgeClass(status) { return status === 'completed' ? 'complete' : status === 'processing' || status === 'partial' ? 'partial' : 'blocked'; }
  function cancelRequests() {
    if (listController) listController.abort(); if (detailController) detailController.abort();
    listController = null; detailController = null; listSequence++; detailSequence++;
  }
  function clearBody() { state.detail = null; state.detailLoading = false; state.detailError = ''; }
  function clearView() {
    cancelRequests(); state.epoch++;
    state.items = []; state.nextCursor = null; state.selected = null; state.listLoading = false; state.listError = ''; state.listLoaded = false; clearBody();
    dom.toast.textContent = ''; dom.toast.classList.remove('visible'); clearTimeout(toastTimer);
    dom['filter-error'].hidden = true;
    renderList(); renderRecord();
  }
  function responseError(status) {
    const error = new Error('History request unavailable'); error.status = status; return error;
  }
  async function requestJson(url, signal) {
    const response = await window.AdminSession.request(url, { method: 'GET', signal });
    if (!response.ok) throw responseError(response.status);
    return response.json();
  }
  function validMetadata(item) {
    return item && typeof item.request_id === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(item.request_id) && Object.hasOwn(statusNames, item.status);
  }
  function listParams() {
    const params = new URLSearchParams({ limit: '50' });
    if (filters.model) params.set('model', filters.model);
    if (filters.protocol) params.set('protocol', filters.protocol);
    if (filters.status) params.set('status', filters.status);
    if (filters.error_code) params.set('error_code', filters.error_code);
    if (filters.created_after) params.set('created_after', filters.created_after);
    if (filters.created_before) params.set('created_before', filters.created_before);
    return params;
  }
  function listFailure(status) {
    if (status === 404) return '请求历史功能未启用。';
    if (status === 422) return '筛选条件无效，请检查模型、错误码与时间范围。';
    return '暂时无法读取历史，请稍后重试。';
  }
  async function loadList(append = false) {
    if (window.AdminSession.isExpired() || (append && !state.nextCursor)) return;
    if (listController) listController.abort();
    const controller = new AbortController(); listController = controller;
    const sequence = ++listSequence, epoch = state.epoch;
    if (!append) { if (detailController) detailController.abort(); detailSequence++; state.items = []; state.nextCursor = null; state.selected = null; clearBody(); }
    state.listLoading = true; state.listError = ''; dom['filter-error'].hidden = true; renderList(); renderRecord();
    const params = listParams();
    if (append) params.set('cursor', state.nextCursor);
    const current = () => epoch === state.epoch && sequence === listSequence;
    try {
      const data = await requestJson('/api/admin/requests?' + params.toString(), controller.signal);
      if (!current()) return;
      if (!data || !Array.isArray(data.items) || !data.items.every(validMetadata) || !(data.next_cursor === null || typeof data.next_cursor === 'string')) throw responseError(0);
      const seen = new Set(state.items.map(item => item.request_id));
      state.items.push(...data.items.filter(item => !seen.has(item.request_id)));
      state.nextCursor = data.next_cursor; state.listLoading = false; state.listLoaded = true;
      renderList(); announce('已加载 ' + state.items.length + ' 条请求。');
      if (!append && state.items.length) selectRecord(state.items[0].request_id, false);
      else renderRecord();
    } catch (error) {
      if (!current() || error.name === 'AbortError') return;
      if (error.status === 401) { clearView(); return; }
      state.items = []; state.nextCursor = null; state.selected = null; clearBody(); state.listLoading = false; state.listLoaded = true;
      state.listError = listFailure(error.status);
      if (error.status === 422) { dom['filter-error'].textContent = state.listError; dom['filter-error'].hidden = false; }
      renderList(); renderRecord();
    } finally { if (current()) { state.listLoading = false; if (listController === controller) listController = null; renderList(); } }
  }
  async function selectRecord(id, focusList = true) {
    if (window.AdminSession.isExpired()) return;
    if (detailController) detailController.abort();
    const controller = new AbortController(); detailController = controller;
    const sequence = ++detailSequence, epoch = state.epoch;
    state.selected = id; clearBody(); state.detailLoading = true; renderList(); renderRecord();
    if (focusList) restoreFocus('request-' + id);
    const current = () => sequence === detailSequence && epoch === state.epoch && state.selected === id;
    try {
      const data = await requestJson('/api/admin/requests/' + encodeURIComponent(id), controller.signal);
      if (!current()) return;
      if (!validMetadata(data) || data.request_id !== id || !Array.isArray(data.stages) || data.stages.length !== 4 || new Set(data.stages.map(stage => stage.stage)).size !== 4 || !data.stages.every(stage => stageInfo.some(info => info.stage === stage.stage) && (stage.state === 'not_produced' ? stage.body === null && stage.media_type === null : ['complete', 'partial'].includes(stage.state) && typeof stage.body === 'string' && ['application/json', 'text/event-stream'].includes(stage.media_type)))) throw responseError(0);
      state.detail = data; state.detailLoading = false; renderRecord(); announce('已加载请求 ' + shortId(id) + ' 的四阶段文本。');
    } catch (error) {
      if (!current() || error.name === 'AbortError') return;
      if (error.status === 401) { clearView(); return; }
      clearBody(); state.detailError = error.status === 404 ? '这条请求不存在或已到期，请刷新列表。' : '暂时无法读取这条请求，已清除已显示正文。请稍后重试。'; renderRecord();
    } finally { if (current() && detailController === controller) detailController = null; }
  }
  function renderList() {
    const list = dom['request-list']; list.replaceChildren(); dom['history-count'].textContent = state.listLoaded ? state.items.length + ' 条' : '';
    list.setAttribute('aria-busy', String(state.listLoading));
    if (!state.items.length) list.append(el('p', 'sidebar-empty', state.listLoading ? '正在读取请求历史…' : state.listError || '没有匹配的请求。试试其他筛选条件。'));
    for (const record of state.items) {
      const button = el('button', 'request-item'); button.type = 'button'; button.id = 'request-' + record.request_id; button.setAttribute('aria-current', String(record.request_id === state.selected));
      button.setAttribute('aria-label', recordName(record) + '，' + statusNames[record.status] + '，' + formatTime(record.created_at));
      const top = el('div', 'item-top'); top.append(el('span', '', formatTime(record.created_at)), el('span', 'status-pill status-' + badgeClass(record.status), statusNames[record.status]));
      const bottom = el('div', 'item-bottom'); bottom.append(el('span', '', String(record.protocol || '协议未提供')), el('span', '', shortId(record.request_id)));
      button.append(top, el('span', 'item-title', recordName(record)), bottom); button.addEventListener('click', () => selectRecord(record.request_id)); list.append(button);
    }
    dom['load-more'].hidden = !state.nextCursor; dom['load-more'].disabled = state.listLoading; dom['load-more'].textContent = state.listLoading ? '正在加载…' : '加载更多';
  }

  // Extract recorded text without rendering model markup or reconstructing redaction.
  function stringValue(value) { return typeof value === 'string' ? value : ''; }
  function serialize(value) { return typeof value === 'string' ? value : JSON.stringify(value); }
  function contentText(value) {
    if (typeof value === 'string') return value;
    if (!Array.isArray(value)) return '';
    return value.map(block => {
      if (!block || typeof block !== 'object') return '';
      if (typeof block.text === 'string') return block.text;
      if (typeof block.thinking === 'string') return '思考内容\n' + block.thinking;
      if (block.type === 'tool_use') return '工具调用' + (block.name ? ' · ' + stringValue(block.name) : '') + '\n' + serialize(block.input ?? {});
      if (block.type === 'tool_result') return '工具结果\n' + contentText(block.content);
      if (typeof block.content === 'string') return block.content;
      return '[非文本内容' + (typeof block.type === 'string' ? ' · ' + block.type : '') + ']';
    }).join('\n\n');
  }
  function messageText(message) {
    if (!message || typeof message !== 'object') return '';
    const pieces = [];
    const content = contentText(message.content); if (content) pieces.push(content);
    const reasoning = stringValue(message.reasoning_content) || stringValue(message.reasoning) || stringValue(message.thinking); if (reasoning) pieces.push('思考内容\n' + reasoning);
    if (Array.isArray(message.tool_calls)) for (const tool of message.tool_calls) {
      if (tool && tool.function) pieces.push('工具调用' + (tool.function.name ? ' · ' + stringValue(tool.function.name) : '') + '\n' + serialize(tool.function.arguments ?? ''));
    }
    if (message.function_call) pieces.push('工具调用' + (message.function_call.name ? ' · ' + stringValue(message.function_call.name) : '') + '\n' + serialize(message.function_call.arguments ?? ''));
    return pieces.join('\n\n');
  }
  function jsonText(body) {
    let value; try { value = JSON.parse(body); } catch { return { text: body, raw: true }; }
    if (!value || typeof value !== 'object' || Array.isArray(value)) return { text: body, raw: true };
    const pieces = []; let recognized = false;
    if ('system' in value) { recognized = true; const system = contentText(value.system); if (system) pieces.push('系统\n' + system); }
    if (Array.isArray(value.messages)) { recognized = true; for (const message of value.messages) { const text = messageText(message); if (text) pieces.push((typeof message.role === 'string' ? ({ user: '用户', assistant: '助手', system: '系统', developer: '开发者', tool: '工具' }[message.role] || message.role) + '\n' : '') + text); } }
    if (Array.isArray(value.choices)) { recognized = true; value.choices.forEach((choice, index) => { const text = messageText(choice.message || choice.delta) || stringValue(choice.text); if (text) pieces.push((value.choices.length > 1 ? '回复 ' + (index + 1) + '\n' : '') + text); }); }
    if ('content' in value) { recognized = true; const text = messageText(value); if (text) pieces.push(text); }
    if (!recognized && typeof value.output_text === 'string') { recognized = true; pieces.push(value.output_text); }
    return recognized ? { text: pieces.join('\n\n'), raw: false } : { text: body, raw: true };
  }
  function streamText(body) {
    const groups = new Map(); let recognized = false, parseFailed = false;
    const group = (key, title) => { if (!groups.has(key)) groups.set(key, { title, text: '', reasoning: '', tools: new Map() }); return groups.get(key); };
    const addTool = (target, key, name, args) => { if (!target.tools.has(key)) target.tools.set(key, { name: '', args: '' }); const tool = target.tools.get(key); tool.name += stringValue(name); tool.args += stringValue(args); };
    for (const frame of body.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split(/\n\n+/)) {
      const lines = frame.split('\n').filter(line => line.startsWith('data:')).map(line => line.slice(5).replace(/^ /, ''));
      if (!lines.length) continue;
      const data = lines.join('\n'); if (!data || data === '[DONE]') continue;
      let event; try { event = JSON.parse(data); } catch { parseFailed = true; continue; }
      if (!event || typeof event !== 'object') { parseFailed = true; continue; }
      if (Array.isArray(event.choices)) {
        recognized = true; for (const choice of event.choices) {
          const index = choice.index ?? 0, target = group('choice-' + index, '回复 ' + (Number(index) + 1)); const delta = choice.delta || choice.message || {};
          target.text += contentText(delta.content) || stringValue(choice.text); target.reasoning += stringValue(delta.reasoning_content) || stringValue(delta.reasoning) || stringValue(delta.thinking);
          if (Array.isArray(delta.tool_calls)) for (const tool of delta.tool_calls) if (tool.function) addTool(target, tool.index ?? tool.id ?? 0, tool.function.name, tool.function.arguments);
          if (delta.function_call) addTool(target, 'function', delta.function_call.name, delta.function_call.arguments);
        }
      } else if (event.type === 'content_block_start') {
        recognized = true; const block = event.content_block || {}, target = group('block-' + (event.index ?? 0), '');
        target.text += stringValue(block.text); target.reasoning += stringValue(block.thinking);
        if (block.type === 'tool_use') addTool(target, 'tool', block.name, block.input && Object.keys(block.input).length ? serialize(block.input) : '');
      } else if (event.type === 'content_block_delta') {
        recognized = true; const delta = event.delta || {}, target = group('block-' + (event.index ?? 0), '');
        target.text += stringValue(delta.text); target.reasoning += stringValue(delta.thinking);
        if (delta.type === 'input_json_delta') addTool(target, 'tool', '', delta.partial_json);
      } else if (event.type === 'message_start') {
        recognized = true; if (event.message && Array.isArray(event.message.content)) event.message.content.forEach((block, index) => { const target = group('block-' + index, ''); if (block.type === 'text') target.text += stringValue(block.text); if (block.type === 'thinking') target.reasoning += stringValue(block.thinking); });
      } else if (['message_delta', 'message_stop', 'content_block_stop', 'ping'].includes(event.type) || 'usage' in event) recognized = true;
      else if (event.type === 'error') { parseFailed = true; }
      else { parseFailed = true; }
    }
    if (parseFailed || !recognized) return { text: body, raw: true };
    const multipleChoices = [...groups.keys()].filter(key => key.startsWith('choice-')).length > 1;
    const pieces = [];
    for (const [key, target] of groups) {
      const texts = []; if (target.text) texts.push(target.text); if (target.reasoning) texts.push('思考内容\n' + target.reasoning);
      for (const tool of target.tools.values()) texts.push('工具调用' + (tool.name ? ' · ' + tool.name : '') + (tool.args ? '\n' + tool.args : ''));
      if (texts.length) pieces.push((multipleChoices && key.startsWith('choice-') ? target.title + '\n' : '') + texts.join('\n\n'));
    }
    return { text: pieces.join('\n\n'), raw: false };
  }
  function stageText(stage) {
    try { return stage.media_type === 'text/event-stream' ? streamText(stage.body) : jsonText(stage.body); }
    catch { return { text: stage.body, raw: true }; }
  }
  function highlightedText(parent, text) {
    if (!state.highlight) { parent.textContent = text; return; }
    let end = 0; for (const match of text.matchAll(/<<ENT_[^<>\r\n]+>>/g)) { parent.append(document.createTextNode(text.slice(end, match.index)), el('mark', 'token', match[0])); end = match.index + match[0].length; }
    parent.append(document.createTextNode(text.slice(end)));
  }
  async function copyStage(index) {
    const info = stageInfo[index], detail = state.detail;
    const stage = detail && detail.stages.find(item => item.stage === info.stage);
    if (!stage || stage.body === null) { notify('该阶段正文未产生，不能复制。'); return; }
    const text = stageText(stage).text;
    try { if (!navigator.clipboard || !navigator.clipboard.writeText) throw responseError(0); await navigator.clipboard.writeText(text); notify('已复制' + info.title + (stage.state === 'partial' ? '（部分内容）' : '') + '。'); }
    catch { notify('浏览器未允许复制，请选择已显示文本手动复制。'); }
  }
  function renderMessage(title, message, buttonText, action) {
    const empty = el('div', 'empty-main', title); if (message) empty.append(el('p', '', message));
    if (action) { const button = el('button', 'control', buttonText); button.type = 'button'; button.addEventListener('click', action); empty.append(button); }
    dom['record-content'].append(empty);
  }
  function renderRecord() {
    const content = dom['record-content']; content.replaceChildren(); content.setAttribute('aria-busy', String(state.detailLoading));
    if (state.listError) { renderMessage('历史暂时不可用', state.listError, '重新加载', () => loadList()); return; }
    if (state.detailLoading) { renderMessage('正在读取文本旅程…', '正在读取所选请求的四阶段内容。'); return; }
    if (state.detailError) { renderMessage('这条请求暂时无法查看', state.detailError, '刷新列表', () => loadList()); return; }
    const record = state.detail;
    if (!record) { if (state.listLoading) renderMessage('正在读取请求历史…', ''); else renderMessage('暂无请求', '当前筛选条件下没有可查看的请求。'); return; }
    const header = el('div', 'record-header'), left = el('div'), title = el('h2', 'record-title', recordName(record));
    title.id = 'record-title'; const meta = el('div', 'record-meta'); meta.append(el('code', '', record.request_id), el('span', '', formatTime(record.created_at)), el('span', '', String(record.protocol || '协议未提供')));
    left.append(title, meta); header.append(left, el('span', 'record-badge ' + (record.status === 'completed' ? '' : badgeClass(record.status)), statusNames[record.status])); content.append(header);
    if (record.status === 'processing') content.append(el('p', 'result-note', '请求仍在处理或结果未确定。现有阶段记录不表示整次请求已完成。'));
    const journey = el('div', 'journey'); journey.setAttribute('aria-label', '处理阶段');
    for (let i = 0; i < 4; i++) { const stage = record.stages.find(item => item.stage === stageInfo[i].stage); const step = el('div', 'journey-step ' + (stage.state === 'not_produced' ? 'unavailable' : stage.state)); step.append(el('span', 'step-circle', stage.state === 'complete' ? '✓' : stage.state === 'partial' ? '~' : '—'), el('span', '', ['输入记录', '脱敏外发', '模型返回', '文本还原'][i])); journey.append(step); } content.append(journey);
    const toolbar = el('div', 'toolbar'), viewTitle = el('div', 'view-title', '四阶段文本对照'); viewTitle.append(el('span', '', '按实际处理顺序排列'));
    const controls = el('div', 'toolbar-controls');
    const highlight = el('button', 'control', (state.highlight ? '✓ ' : '') + '高亮占位符'); highlight.type = 'button'; highlight.id = 'highlight-toggle'; highlight.setAttribute('aria-pressed', String(state.highlight)); highlight.addEventListener('click', () => { state.highlight = !state.highlight; renderRecord(); restoreFocus('highlight-toggle'); }); controls.append(highlight); toolbar.append(viewTitle, controls); content.append(toolbar);
    const grid = el('div', 'panel-grid');
    for (let index = 0; index < 4; index++) {
      const info = stageInfo[index], stage = record.stages.find(item => item.stage === info.stage), panel = el('article', 'panel'); panel.setAttribute('aria-labelledby', 'stage-title-' + index);
      const head = el('div', 'panel-head'), label = el('div', 'panel-label'), labelText = el('div'), stageTitle = el('h3', '', info.title); stageTitle.id = 'stage-title-' + index; labelText.append(stageTitle, el('div', 'panel-sub', info.en)); label.append(el('span', 'panel-num', '0' + (index + 1)), labelText);
      const copy = el('button', 'copy-btn'); copy.type = 'button'; copy.append(icon('copy'), el('span', '', '复制文本')); copy.setAttribute('aria-label', '复制' + info.title + (stage.state === 'partial' ? '的部分内容' : '')); copy.disabled = stage.body === null; copy.title = copy.disabled ? '该阶段未产生正文' : '复制当前显示的文本'; copy.addEventListener('click', () => copyStage(index)); head.append(label, copy); panel.append(head);
      const body = el('div', 'panel-body'); let raw = false;
      if (stage.state === 'not_produced') {
        const missing = el('div', 'missing-content'); missing.append(el('div', 'missing-symbol', '—'), el('strong', '', '未产生'), el('p', '', record.status === 'processing' ? '该阶段尚无正文记录，整次请求的结果仍未确定。' : '这次请求没有产生该阶段的正文。')); body.append(missing);
      } else {
        const displayed = stageText(stage); raw = displayed.raw;
        if (!displayed.text) { const empty = el('div', 'missing-content'); empty.append(el('strong', '', '正文为空'), el('p', '', '已记录的内容中没有可显示文本。')); body.append(empty); }
        else { const text = el('p', 'text-content'); highlightedText(text, displayed.text); body.append(text); }
      }
      panel.append(body); const foot = el('div', 'panel-foot ' + (stage.state === 'not_produced' ? 'unavailable' : stage.state));
      const note = stage.state === 'not_produced' ? '未产生' : stage.state === 'partial' ? '部分内容 · 未补全' : ['入站请求正文', '实际外发正文', '模型原始响应 · 尚未还原', '已生成的最终正文'][index]; foot.append(el('span', 'foot-dot'), el('span', '', note + (raw ? ' · 原报文纯文本' : ''))); panel.append(foot); grid.append(panel);
    }
    content.append(grid); const explanation = el('div', 'explanation'), legend = el('div', 'legend'), legendItem = el('span', 'legend-item'); legendItem.append(el('span', 'legend-color'), el('span', '', '原报文中的替换占位符')); legend.append(legendItem);
    const ending = []; if (record.error_code) ending.push('状态代码：' + String(record.error_code)); if (record.expires_at) ending.push('保留至 ' + formatTime(record.expires_at)); explanation.append(legend, el('span', '', ending.join(' · '))); content.append(explanation);
  }

  function readFilters() {
    const next = {
      model: dom['filter-model'].value.trim(),
      protocol: dom['filter-protocol'].value,
      status: dom['filter-status'].value,
      error_code: dom['filter-error-code'].value.trim(),
      created_after: dom['filter-created-after'].value,
      created_before: dom['filter-created-before'].value
    };
    const toIso = value => new Date(value).toISOString().replace('Z', '+00:00');
    if (next.created_after && next.created_before && new Date(next.created_after) > new Date(next.created_before)) return null;
    next.created_after = next.created_after ? toIso(next.created_after) : '';
    next.created_before = next.created_before ? toIso(next.created_before) : '';
    return next;
  }
  function applyFilters() {
    const next = readFilters();
    if (next === null) {
      dom['filter-error'].textContent = '开始时间不能晚于结束时间。';
      dom['filter-error'].hidden = false;
      return;
    }
    Object.assign(filters, next);
    loadList();
  }

  dom['history-filters'].addEventListener('submit', event => { event.preventDefault(); applyFilters(); });
  dom['filter-reset'].addEventListener('click', () => {
    dom['filter-model'].value = ''; dom['filter-protocol'].value = ''; dom['filter-status'].value = '';
    dom['filter-error-code'].value = ''; dom['filter-created-after'].value = ''; dom['filter-created-before'].value = '';
    Object.keys(filters).forEach(key => { filters[key] = ''; });
    dom['filter-error'].hidden = true;
    loadList();
  });
  dom['refresh-history'].addEventListener('click', () => loadList());
  dom['load-more'].addEventListener('click', () => loadList(true));
  window.addEventListener('pagehide', () => { cancelRequests(); state.epoch++; });
  window.AdminSession.onExpire(clearView);
  renderList(); renderRecord();
  window.AdminSession.ready().then(() => loadList(), error => {
    if (error && error.status === 401) { clearView(); return; }
    state.listLoading = false; state.listLoaded = true; state.listError = '暂时无法确认会话状态，请稍后重试。';
    renderList(); renderRecord();
  });
})();
