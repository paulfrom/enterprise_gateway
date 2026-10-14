"""Synthetic in-memory documents exercise parsers and omitted-content gates."""
from io import BytesIO
import unittest
import zipfile

from openpyxl import Workbook
from openpyxl.comments import Comment
from pypdf import PdfWriter
from pypdf.generic import DictionaryObject, NameObject, DecodedStreamObject

from document.extract import DocumentError, extract_document

PHONE = '13800138000'
W = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'


def docx(extra=None, body=None):
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, 'w') as package:
        package.writestr('word/document.xml', body or (
            f'<w:document xmlns:w="{W}"><w:body><w:p><w:r><w:t>{PHONE[:5]}</w:t></w:r>'
            f'<w:r><w:t>{PHONE[5:]}</w:t></w:r></w:p><w:tbl><w:tr><w:tc>'
            '<w:p><w:r><w:t>星云科技</w:t></w:r></w:p></w:tc></w:tr></w:tbl></w:body></w:document>'))
        for name, value in (extra or {}).items():
            package.writestr(name, value)
    return buffer.getvalue()


def spreadsheet():
    book = Workbook()
    sheet = book.active
    sheet.title = '星云科技'
    sheet['A1'] = PHONE
    sheet['B1'] = '星云科技'
    sheet['A2'] = '=SUM(1,2)'
    sheet['B3'].comment = Comment(PHONE, '合成作者')
    sheet.row_dimensions[1].hidden = True
    hidden = book.create_sheet('隐藏')
    hidden.sheet_state = 'hidden'
    hidden['A1'] = PHONE
    buffer = BytesIO()
    book.save(buffer)
    book.close()
    return buffer.getvalue()


def pdf(text=PHONE):
    writer = PdfWriter()
    page = writer.add_blank_page(width=300, height=300)
    if text:
        font = DictionaryObject({NameObject('/Type'): NameObject('/Font'), NameObject('/Subtype'): NameObject('/Type1'),
                                 NameObject('/BaseFont'): NameObject('/Helvetica')})
        page[NameObject('/Resources')] = DictionaryObject({NameObject('/Font'): DictionaryObject({NameObject('/F1'): font})})
        stream = DecodedStreamObject()
        stream.set_data(f'BT /F1 12 Tf 20 200 Td ({text}) Tj ET'.encode('ascii'))
        page[NameObject('/Contents')] = writer._add_object(stream)
    buffer = BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


class ExtractionTests(unittest.TestCase):
    def test_text_formats_preserve_all_source_text(self):
        for fmt in ('txt', 'md', 'json', 'yaml', 'yml'):
            text = '  星云科技\r\nhttps://example.test/' + PHONE + '\n'
            parsed = extract_document(('\ufeff' + text).encode(), fmt)
            self.assertEqual((text,), parsed.blocks[0].texts)

    def test_csv_keeps_multiline_and_literal_delimiters(self):
        parsed = extract_document(f'公司,电话\n"星云|科技\n组织",{PHONE}'.encode(), 'csv')
        self.assertEqual(('星云|科技\n组织', PHONE), parsed.blocks[1].texts)

    def test_docx_reads_runs_tables_and_ancillary_content(self):
        data = docx({'word/header1.xml': f'<w:hdr xmlns:w="{W}"><w:p><w:r><w:t>{PHONE}</w:t></w:r></w:p></w:hdr>',
                     'word/comments.xml': f'<w:comments xmlns:w="{W}"><w:comment><w:p><w:r><w:t>批注 {PHONE}</w:t></w:r></w:p></w:comment></w:comments>'})
        parsed = extract_document(data, 'docx')
        values = [value for block in parsed.blocks for value in block.texts]
        self.assertIn(PHONE, values)
        self.assertIn('星云科技', values)
        self.assertIn('批注 ' + PHONE, values)
        self.assertIn('DOCX_ANCILLARY_INCLUDED', parsed.warnings)

    def test_spreadsheet_includes_hidden_titles_formulas_and_comments(self):
        parsed = extract_document(spreadsheet(), 'xlsx')
        values = [value for block in parsed.blocks for value in block.texts]
        self.assertEqual(3, sum(value == PHONE for value in values))
        self.assertIn('星云科技', values)
        self.assertIn('=SUM(1,2)', values)
        self.assertIn('SPREADSHEET_HIDDEN_CONTENT_INCLUDED', parsed.warnings)
        self.assertIn('SPREADSHEET_COMMENTS_INCLUDED', parsed.warnings)

    def test_pdf_text_and_blank_page(self):
        self.assertIn(PHONE, extract_document(pdf(), 'pdf').blocks[0].texts[0])
        with self.assertRaises(DocumentError) as caught:
            extract_document(pdf(''), 'pdf')
        self.assertEqual('DOCUMENT_NO_TEXT', caught.exception.code)

    def test_unsafe_and_malformed_documents_fail_without_diagnostics(self):
        cases = [
            (docx({'word/media/image1.png': b'canary'}), 'docx', 'DOCUMENT_UNSUPPORTED_CONTENT'),
            (docx({'word/embeddings/ole.bin': b'canary'}), 'docx', 'DOCUMENT_UNSUPPORTED_CONTENT'),
            (docx(body=f'<!DOCTYPE a [<!ENTITY x "{PHONE}">]><w:document xmlns:w="{W}">&x;</w:document>'), 'docx', 'DOCUMENT_INVALID'),
            (b'PK corrupt ' + PHONE.encode(), 'docx', 'DOCUMENT_INVALID'),
            (b'\xff' + PHONE.encode(), 'txt', 'DOCUMENT_INVALID'),
            (b'\x00' + PHONE.encode(), 'txt', 'DOCUMENT_INVALID'),
            (b'', 'txt', 'DOCUMENT_NO_TEXT'),
            (PHONE.encode(), 'doc', 'DOCUMENT_FORMAT_UNSUPPORTED'),
            (('A' * 200001).encode(), 'txt', 'DOCUMENT_LIMIT_EXCEEDED'),
            (docx(body=f'<w:document xmlns:w="{W}"><w:body><w:tbl><w:tr>' + '<w:tc/>' * 257
                       + '</w:tr></w:tbl></w:body></w:document>'), 'docx', 'DOCUMENT_LIMIT_EXCEEDED'),
        ]
        bomb = BytesIO()
        with zipfile.ZipFile(bomb, 'w', compression=zipfile.ZIP_DEFLATED) as package:
            package.writestr('word/document.xml', 'A' * 100000)
        cases.append((bomb.getvalue(), 'docx', 'DOCUMENT_LIMIT_EXCEEDED'))
        for data, fmt, expected in cases:
            with self.subTest(fmt=fmt, expected=expected), self.assertRaises(DocumentError) as caught:
                extract_document(data, fmt)
            self.assertEqual(expected, caught.exception.code)
            self.assertNotIn(PHONE, str(caught.exception))
