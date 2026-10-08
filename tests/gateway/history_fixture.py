import uuid
from request_history.models import HistoryUnavailable


class RecorderSpy:
    max_stage_bytes = 16777216

    def __init__(self, fail_stage=None, fail_finish=False):
        self.request_id = str(uuid.uuid4())
        self.fail_stage = fail_stage
        self.fail_finish = fail_finish
        self.stages = {}
        self.status = 'processing'
        self.error_code = None
        self.transactions = []

    def write(self, stage, body, *, media_type='application/json', state='complete', append=False):
        self.write_many([dict(stage=stage, body=body, media_type=media_type, state=state, append=append)])

    def write_many(self, updates):
        if any(update['stage'] == self.fail_stage for update in updates):
            raise HistoryUnavailable()
        self.transactions.append(updates)
        for update in updates:
            stage = update['stage']
            old = self.stages.get(stage, {}).get('body', b'') if update.get('append') else b''
            self.stages[stage] = {**update, 'body': old + update['body']}

    def finish(self, status, error_code=None):
        if self.fail_finish:
            raise HistoryUnavailable()
        self.status, self.error_code = status, error_code


class StoreSpy:
    def __init__(self, recorder):
        self.recorder = recorder
        self.fail_ready = False

    def check_ready(self):
        if self.fail_ready:
            raise HistoryUnavailable()

    def begin(self, *, protocol, model, raw_body):
        self.recorder.write('input', raw_body)
        return self.recorder


