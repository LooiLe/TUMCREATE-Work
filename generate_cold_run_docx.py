import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import parse_xml
from docx.oxml.ns import nsdecls

def create_document():
    doc = docx.Document()

    for section in doc.sections:
        section.top_margin = Inches(0.8)
        section.bottom_margin = Inches(0.8)
        section.left_margin = Inches(0.8)
        section.right_margin = Inches(0.8)

    def set_cell_background(cell, fill_hex):
        shading_elm = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
        cell._tc.get_or_add_tcPr().append(shading_elm)

    def set_cell_margins(cell, top=100, bottom=100, left=120, right=120):
        tcPr = cell._tc.get_or_add_tcPr()
        tcMar = parse_xml(f'<w:tcMar {nsdecls("w")}><w:top w:w="{top}" w:type="dxa"/><w:bottom w:w="{bottom}" w:type="dxa"/><w:left w:w="{left}" w:type="dxa"/><w:right w:w="{right}" w:type="dxa"/></w:tcMar>')
        tcPr.append(tcMar)

    def add_table_borders(table):
        tblPr = table._tbl.tblPr
        borders = parse_xml(
            f'<w:tblBorders {nsdecls("w")}>'
            '<w:top w:val="single" w:sz="8" w:space="0" w:color="1F3864"/>'
            '<w:bottom w:val="single" w:sz="8" w:space="0" w:color="1F3864"/>'
            '<w:insideH w:val="single" w:sz="4" w:space="0" w:color="D9E1F2"/>'
            '<w:insideV w:val="none"/>'
            '<w:left w:val="none"/>'
            '<w:right w:val="none"/>'
            '</w:tblBorders>'
        )
        tblPr.append(borders)

    # Title
    p = doc.add_paragraph()
    r = p.add_run('CVA6 Cold RAM-to-Register Benchmark Results (1 Iteration + Reset)')
    r.font.name = 'Calibri'
    r.font.size = Pt(14)
    r.font.bold = True
    r.font.color.rgb = RGBColor(0x1F, 0x38, 0x64)

    sub = doc.add_paragraph()
    sub_r = sub.add_run('Payload: 4,096 Bytes | Frequency: 50 MHz | Hardware Reset between Runs')
    sub_r.font.name = 'Calibri'
    sub_r.font.size = Pt(10)
    sub_r.font.italic = True
    sub_r.font.color.rgb = RGBColor(0x59, 0x59, 0x59)

    # TABLE 1: Cold Run Benchmark Results
    headers1 = [
        'Algorithm',
        'Block size\n(bits)',
        'Digest size\n(bits)',
        'Datapath size\n(bits)',
        'Clk. Cycles',
        'Instructions',
        'Time (s) @\n50MHz'
    ]

    data1 = [
        ('SHA2-224', '512', '224', '32', '280,045', '247,142', '0.005601'),
        ('SHA2-256', '512', '256', '32', '279,851', '247,133', '0.005597'),
        ('SHA2-384', '1024', '384', '64', '204,596', '165,733', '0.004092'),
        ('SHA2-512', '1024', '512', '64', '204,665', '165,791', '0.004093'),
        ('SHA2-512/224', '1024', '224', '64', '204,847', '165,790', '0.004097'),
        ('SHA2-512/256', '1024', '256', '64', '204,721', '165,771', '0.004094'),
        ('SHA3-224', '1152', '224', '64', '252,879', '203,677', '0.005058'),
        ('SHA3-256', '1088', '256', '64', '267,902', '215,798', '0.005358'),
        ('SHA3-384', '832', '384', '64', '340,875', '277,631', '0.006817'),
        ('SHA3-512', '576', '512', '64', '479,850', '394,522', '0.009597'),
        ('SHAKE-128', '1344', '256', '64', '220,692', '176,161', '0.004414'),
        ('SHAKE-256', '1088', '512', '64', '268,146', '215,837', '0.005363'),
    ]

    table1 = doc.add_table(rows=len(data1) + 1, cols=7)
    table1.alignment = WD_TABLE_ALIGNMENT.CENTER
    add_table_borders(table1)

    for i, h in enumerate(headers1):
        cell = table1.cell(0, i)
        set_cell_background(cell, '1F3864')
        set_cell_margins(cell, top=120, bottom=120, left=100, right=100)
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(h)
        run.font.name = 'Calibri'
        run.font.size = Pt(9.5)
        run.font.bold = True
        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)

    for r_idx, row_data in enumerate(data1):
        bg = 'F2F4F8' if r_idx % 2 == 1 else 'FFFFFF'
        for c_idx, val in enumerate(row_data):
            cell = table1.cell(r_idx + 1, c_idx)
            set_cell_background(cell, bg)
            set_cell_margins(cell, top=80, bottom=80, left=100, right=100)
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.LEFT if c_idx == 0 else WD_ALIGN_PARAGRAPH.CENTER
            run = p.add_run(val)
            run.font.name = 'Calibri'
            run.font.size = Pt(9.5)
            if c_idx == 0:
                run.font.bold = True

    # Spacing
    doc.add_paragraph()

    # TABLE 2: Warm Run vs Cold Run Comparison (RAM Load Penalty)
    p2 = doc.add_paragraph()
    r2 = p2.add_run('Table 2: Comparison — Warm Cache vs. Cold RAM Load (1 Iteration + Reset)')
    r2.font.name = 'Calibri'
    r2.font.size = Pt(12)
    r2.font.bold = True
    r2.font.color.rgb = RGBColor(0x1F, 0x38, 0x64)

    headers2 = [
        'Algorithm',
        'Warm Cycles',
        'Cold Cycles (1 Iter)',
        'RAM Load Overhead',
        'Warm Time (s)',
        'Cold Time (s)'
    ]

    data2 = [
        ('SHA2-224', '253,888', '280,045', '+10.30% (+26,157 cyc)', '0.005079', '0.005601'),
        ('SHA2-256', '253,920', '279,851', '+10.21% (+25,931 cyc)', '0.005078', '0.005597'),
        ('SHA2-384', '177,633', '204,596', '+15.18% (+26,963 cyc)', '0.003553', '0.004092'),
        ('SHA2-512', '177,659', '204,665', '+15.20% (+27,006 cyc)', '0.003554', '0.004093'),
        ('SHA2-512/224', '177,635', '204,847', '+15.32% (+27,212 cyc)', '0.003554', '0.004097'),
        ('SHA2-512/256', '177,635', '204,721', '+15.25% (+27,086 cyc)', '0.003553', '0.004094'),
        ('SHA3-224', '246,293', '252,879', '+2.67% (+6,586 cyc)', '0.004926', '0.005058'),
        ('SHA3-256', '262,551', '267,902', '+2.04% (+5,351 cyc)', '0.005251', '0.005358'),
        ('SHA3-384', '336,223', '340,875', '+1.38% (+4,652 cyc)', '0.006725', '0.006817'),
        ('SHA3-512', '475,319', '479,850', '+0.95% (+4,531 cyc)', '0.009507', '0.009597'),
        ('SHAKE-128', '213,623', '220,692', '+3.31% (+7,069 cyc)', '0.004273', '0.004414'),
        ('SHAKE-256', '262,663', '268,146', '+2.09% (+5,483 cyc)', '0.005254', '0.005363'),
    ]

    table2 = doc.add_table(rows=len(data2) + 1, cols=6)
    table2.alignment = WD_TABLE_ALIGNMENT.CENTER
    add_table_borders(table2)

    for i, h in enumerate(headers2):
        cell = table2.cell(0, i)
        set_cell_background(cell, '1F3864')
        set_cell_margins(cell, top=120, bottom=120, left=100, right=100)
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(h)
        run.font.name = 'Calibri'
        run.font.size = Pt(9.5)
        run.font.bold = True
        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)

    for r_idx, row_data in enumerate(data2):
        bg = 'F2F4F8' if r_idx % 2 == 1 else 'FFFFFF'
        for c_idx, val in enumerate(row_data):
            cell = table2.cell(r_idx + 1, c_idx)
            set_cell_background(cell, bg)
            set_cell_margins(cell, top=80, bottom=80, left=100, right=100)
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.LEFT if c_idx == 0 else WD_ALIGN_PARAGRAPH.CENTER
            run = p.add_run(val)
            run.font.name = 'Calibri'
            run.font.size = Pt(9.5)
            if c_idx == 0:
                run.font.bold = True
            if c_idx == 3:
                run.font.bold = True

    # Note
    note = doc.add_paragraph()
    note_r = note.add_run('\nArchitectural Note: Every single algorithm executed exactly 29 fewer retired instructions compared to the multi-algorithm loop build (due to compiler loop/switch pruning in the single-target build). The +26k clock cycle increase in SHA-2 represents the pure hardware latency of cold L1 cache misses fetching instructions and the 4 KB test payload across the AXI bus from DRAM/SRAM into CPU registers.')
    note_r.font.name = 'Calibri'
    note_r.font.size = Pt(9)
    note_r.font.italic = True
    note_r.font.color.rgb = RGBColor(0x59, 0x59, 0x59)

    out_file1 = r'c:\Users\looil\Desktop\Intern\TUMCREATE\work\ml-dsa\hashing_algorithm_benchmark_cold_run.docx'
    doc.save(out_file1)
    print("Saved to:", out_file1)

    try:
        out_file2 = r'c:\Users\looil\Desktop\Intern\TUMCREATE\work\ml-dsa\hashing_algorithm_benchmark_and_comparison.docx'
        doc.save(out_file2)
        print("Saved to:", out_file2)
    except Exception as e:
        print("Note: Could not overwrite hashing_algorithm_benchmark_and_comparison.docx (file open):", e)

if __name__ == '__main__':
    create_document()
