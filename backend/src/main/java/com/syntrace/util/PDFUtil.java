package com.syntrace.util;

import com.lowagie.text.Chunk;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.FontFactory;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.syntrace.entity.Severity;

import java.awt.Color;

/**
 * MODULE 9 - typography and table primitives for the OpenPDF report engine.
 *
 * <p>Keeping fonts, palette and cell construction here means the report generator reads as
 * document structure rather than as a wall of styling calls, and the visual identity can be
 * changed in one file.</p>
 */
public final class PDFUtil {

    private PDFUtil() {
    }

    /** Deep slate used for headings and the header band. */
    public static final Color INK = new Color(15, 23, 42);

    /** Muted slate used for labels and secondary text. */
    public static final Color MUTED = new Color(100, 116, 139);

    /** Accent cyan matching the SynTrace console. */
    public static final Color ACCENT = new Color(14, 165, 233);

    /** Very light slate used for zebra rows and panels. */
    public static final Color PANEL = new Color(241, 245, 249);

    /** Hairline colour for table borders. */
    public static final Color HAIRLINE = new Color(203, 213, 225);

    public static final Font TITLE = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 22, Color.WHITE);
    public static final Font SUBTITLE = FontFactory.getFont(FontFactory.HELVETICA, 10, new Color(186, 230, 253));
    public static final Font H1 = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 13, INK);
    public static final Font H2 = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, INK);
    public static final Font BODY = FontFactory.getFont(FontFactory.HELVETICA, 9.5f, INK);
    public static final Font BODY_BOLD = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 9.5f, INK);
    public static final Font SMALL = FontFactory.getFont(FontFactory.HELVETICA, 8, MUTED);
    public static final Font MONO = FontFactory.getFont(FontFactory.COURIER, 8, INK);
    public static final Font TABLE_HEAD = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 8.5f, Color.WHITE);

    /**
     * @param severity severity to colour, may be {@code null}
     * @return badge colour for the severity band
     */
    public static Color colourFor(Severity severity) {
        if (severity == null) {
            return MUTED;
        }
        return switch (severity) {
            case CRITICAL -> new Color(190, 18, 60);
            case HIGH -> new Color(234, 88, 12);
            case MEDIUM -> new Color(202, 138, 4);
            case LOW -> new Color(21, 128, 61);
            case INFO -> MUTED;
        };
    }

    /**
     * @param text  section title
     * @return a spaced, underlined section heading
     */
    public static Paragraph sectionTitle(String text) {
        Paragraph paragraph = new Paragraph(text.toUpperCase(), H1);
        paragraph.setSpacingBefore(16f);
        paragraph.setSpacingAfter(6f);
        return paragraph;
    }

    /**
     * @param text body copy
     * @return justified body paragraph
     */
    public static Paragraph body(String text) {
        Paragraph paragraph = new Paragraph(LogUtil.orDefault(text, "-"), BODY);
        paragraph.setAlignment(Element.ALIGN_JUSTIFIED);
        paragraph.setLeading(13f);
        paragraph.setSpacingAfter(4f);
        return paragraph;
    }

    /**
     * @param text bullet copy
     * @return an indented bulleted line
     */
    public static Paragraph bullet(String text) {
        Paragraph paragraph = new Paragraph();
        paragraph.add(new Chunk("\u2022  ", BODY_BOLD));
        paragraph.add(new Chunk(LogUtil.orDefault(text, "-"), BODY));
        paragraph.setIndentationLeft(12f);
        paragraph.setLeading(13f);
        paragraph.setSpacingAfter(3f);
        return paragraph;
    }

    /**
     * @param widths relative column widths
     * @return a full-width table with sane defaults
     */
    public static PdfPTable table(float... widths) {
        PdfPTable table = new PdfPTable(widths);
        table.setWidthPercentage(100f);
        table.setSpacingBefore(6f);
        table.setSpacingAfter(6f);
        table.getDefaultCell().setBorderColor(HAIRLINE);
        return table;
    }

    /**
     * @param text header label
     * @return a dark header cell
     */
    public static PdfPCell headerCell(String text) {
        PdfPCell cell = new PdfPCell(new Phrase(text.toUpperCase(), TABLE_HEAD));
        cell.setBackgroundColor(INK);
        cell.setBorderColor(INK);
        cell.setPadding(6f);
        return cell;
    }

    /**
     * @param text   cell copy
     * @param zebra  whether to shade the row
     * @return a body cell
     */
    public static PdfPCell cell(String text, boolean zebra) {
        return cell(text, BODY, zebra);
    }

    /**
     * @param text  cell copy
     * @param font  font to render with
     * @param zebra whether to shade the row
     * @return a body cell
     */
    public static PdfPCell cell(String text, Font font, boolean zebra) {
        PdfPCell cell = new PdfPCell(new Phrase(LogUtil.orDefault(text, "-"), font));
        cell.setBorderColor(HAIRLINE);
        cell.setPadding(5f);
        if (zebra) {
            cell.setBackgroundColor(PANEL);
        }
        return cell;
    }

    /**
     * @param severity severity to render
     * @param zebra    whether to shade the row
     * @return a colour-coded severity cell
     */
    public static PdfPCell severityCell(Severity severity, boolean zebra) {
        String label = severity == null ? "-" : severity.name();
        PdfPCell cell = new PdfPCell(new Phrase(label,
                FontFactory.getFont(FontFactory.HELVETICA_BOLD, 8.5f, colourFor(severity))));
        cell.setBorderColor(HAIRLINE);
        cell.setPadding(5f);
        if (zebra) {
            cell.setBackgroundColor(PANEL);
        }
        return cell;
    }

    /**
     * A label/value pair rendered as a compact metadata row.
     *
     * @param label field name
     * @param value field value
     * @param zebra whether to shade the row
     * @return two-cell array ready to add to a two-column table
     */
    public static PdfPCell[] metaRow(String label, String value, boolean zebra) {
        PdfPCell key = cell(label, BODY_BOLD, zebra);
        PdfPCell val = cell(value, BODY, zebra);
        return new PdfPCell[]{key, val};
    }
}
