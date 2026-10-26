# Kinds of mail content the plugin must turn into readable text (owner 2026-10-26).
# Run: python3 -m pytest plugin/test. All example mails are made up.
import pathlib
import sys
from email.message import EmailMessage
from email.mime.message import MIMEMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))
import transform  # noqa: E402

ZW = '‌ ​͏﻿' * 40  # the padding newsletters put after a preheader


def html_mail(html, plain=None):
    msg = EmailMessage()
    msg['From'], msg['Subject'], msg['Date'] = 'News <news@shop.example>', 'Autumn sale', 'Sat, 25 Oct 2026 09:00:00 +0000'
    if plain is not None:
        msg.set_content(plain)
        msg.add_alternative(html, subtype='html')
    else:
        msg.set_content(html, subtype='html')
    return msg.as_bytes()


def body_of(raw, max_chars=transform.MAX_BODY_CHARS):
    return transform.parse_full_message(raw, b'', True, max_chars)['body']


NEWSLETTER = ('<html><head><style>' + '.c{color:#123456;margin:0 auto;padding:4px 8px}\n' * 900 + '</style></head><body>'
              '<div style="display:none;max-height:0;overflow:hidden">Our biggest sale starts today' + ZW + '</div>'
              '<table><tr><td><h1>Autumn sale</h1></td></tr>'
              '<tr><td><p>Everything 30% off until Sunday.</p></td><td><p>Free delivery over 50 euro.</p></td></tr></table>'
              '<p style="font-size:0;line-height:0">tracking-id-123</p></body></html>')


def test_newsletter_text_after_a_lot_of_css():
    assert len(NEWSLETTER) > 40_000  # more style than the first fetch window holds
    body = body_of(html_mail(NEWSLETTER))
    assert body.startswith('Autumn sale') and 'Everything 30% off until Sunday.' in body


def test_hidden_preheader_and_zero_width_padding_are_left_out():
    body = body_of(html_mail(NEWSLETTER))
    assert 'Our biggest sale starts today' not in body and 'tracking-id-123' not in body
    assert not any(ch in body for ch in '‌​͏﻿')


def test_table_cells_do_not_run_together():
    receipt = ('<table><tr><td>Coffee beans</td><td>12.50</td></tr><tr><td>Filter papers</td><td>3.20</td></tr>'
               '<tr><td><b>Total</b></td><td><b>15.70</b></td></tr></table>')
    lines = body_of(html_mail(receipt)).split('\n')
    assert lines == ['Coffee beans 12.50', 'Filter papers 3.20', 'Total 15.70']


def test_a_stub_plain_part_gives_way_to_the_html():
    plain = 'View this email in your browser: https://shop.example/view/abc'
    html = '<p>Your parcel will arrive on Tuesday between 9 and 12.</p>'
    assert body_of(html_mail(html, plain=plain)) == 'Your parcel will arrive on Tuesday between 9 and 12.'


def test_a_real_plain_part_is_still_preferred():
    plain = 'Hi Anna,\n\nThe meeting moved to Thursday at 10.\n\nBob'
    html = '<p>Hi Anna,</p><p>The meeting moved to <b>Thursday at 10</b>.</p><p>Bob</p>'
    assert body_of(html_mail(html, plain=plain)) == plain


def test_a_mail_forwarded_as_attachment_shows_its_own_text():
    outer = MIMEMultipart('mixed')
    outer['From'], outer['Subject'] = 'bob@example.com', 'Fwd: Invoice'
    outer.attach(MIMEText('See the attached mail, can you check it?'))
    inner = EmailMessage()
    inner['From'], inner['Subject'] = 'billing@example.com', 'Invoice'
    inner.set_content('Invoice 42 is due on Friday.')
    outer.attach(MIMEMessage(inner))
    assert body_of(outer.as_bytes()) == 'See the attached mail, can you check it?'


def test_format_flowed_lines_are_joined():
    msg = EmailMessage()
    msg['From'], msg['Subject'] = 'a@example.com', 'Flowed'
    msg.set_content('This is a long sentence that the sender\'s mail program wrapped \nat the end of a line.\n\nNew paragraph.')
    msg.replace_header('Content-Type', 'text/plain; charset="utf-8"; format=flowed')
    assert transform.parse_full_message(msg.as_bytes(), b'')['paragraphs'] == [
        "This is a long sentence that the sender's mail program wrapped at the end of a line.", 'New paragraph.']


def test_a_bounce_shows_the_readable_report():
    raw = (b'From: MAILER-DAEMON@example.com\r\nSubject: Undelivered Mail Returned to Sender\r\nMIME-Version: 1.0\r\n'
           b'Content-Type: multipart/report; report-type=delivery-status; boundary="b"\r\n\r\n'
           b'--b\r\nContent-Type: text/plain\r\n\r\nYour message to bob@nowhere.example could not be delivered.\r\n'
           b'--b\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; mail.example\r\n\r\n'
           b'Final-Recipient: rfc822; bob@nowhere.example\r\nStatus: 5.1.1\r\n--b--\r\n')
    assert body_of(raw) == 'Your message to bob@nowhere.example could not be delivered.'


def test_emoji_and_other_scripts_pass_through():
    msg = EmailMessage()
    msg['From'], msg['Subject'] = '田中 <t@example.jp>', '🎉 パーティー'
    msg.set_content('Привет! 你好 🎃 مرحبا')
    m = transform.parse_full_message(msg.as_bytes(), b'')
    assert m['body'] == 'Привет! 你好 🎃 مرحبا' and m['subject'] == '🎉 パーティー' and m['sender'] == '田中'
