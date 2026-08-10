package com.syntrace.report;

import com.lowagie.text.Document;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Element;
import com.lowagie.text.Image;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.PdfContentByte;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfPageEventHelper;
import com.lowagie.text.pdf.PdfWriter;
import com.syntrace.common.AppConstants;
import com.syntrace.dto.RecommendationDTO;
import com.syntrace.dto.ReportDTO;
import com.syntrace.dto.ThreatDTO;
import com.syntrace.dto.TimelineDTO;
import com.syntrace.exception.ReportException;
import com.syntrace.util.DateUtil;
import com.syntrace.util.LogUtil;
import com.syntrace.util.PDFUtil;
import com.syntrace.util.RiskCalculator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * MODULE 1 - renders a {@link ReportDTO} into a print-ready incident report using OpenPDF.
 *
 * <p>Layout, top to bottom: branded header band with a logo placeholder, case metadata
 * block, executive summary, risk panel, threat summary table, attack story, reconstructed
 * timeline, root cause callout, MITRE ATT&amp;CK mapping, affected devices and accounts,
 * recommendations, containment actions and a chain-of-custody footer.</p>
 *
 * <p>Everything renders offline from local fonts. No network fetch, no remote font, no
 * external image - the document must build identically on an air-gapped machine.</p>
 */
@Slf4j
@Component
public class PdfReportGenerator {

    private static final float MARGIN = 42f;
    private static final String LOGO_CLASSPATH = "branding/logo.png";

    /**
     * Renders the report.
     *
     * @param report assembled report payload
     * @return PDF bytes
     */
    public byte[] render(ReportDTO report) {
        if (report == null) {
            throw new ReportException("No report payload supplied");
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream(64 * 1024);
        Document document = new Document(PageSize.A4, MARGIN, MARGIN, MARGIN, 54f);

        try {
            PdfWriter writer = PdfWriter.getInstance(document, out);
            writer.setPageEvent(new FooterEvent(report));
            document.addTitle(AppConstants.PRODUCT_NAME + " Incident Report " + report.incidentCode());
            document.addSubject(LogUtil.orDefault(report.title(), "Security incident"));
            document.addCreator(AppConstants.PRODUCT_NAME);
            document.open();

            header(document, report);
            metadata(document, report);
            executiveSummary(document, report);
            riskPanel(document, report);
            threatSummary(document, report.threats());
            attackStory(document, report);
            timeline(document, report.timeline());
            rootCause(document, report);
            mitreMapping(document, report.mitreTechniques(), report.threats());
            affectedAssets(document, report);
            recommendations(document, report.recommendations());
            containment(document, report.recommendations());
            chainOfCustody(document, report);

            document.close();
            log.info("REPORT RENDERED - incident={} bytes={}", report.incidentCode(), out.size());
            return out.toByteArray();
        } catch (DocumentException ex) {
            throw new ReportException("Failed to render the incident report PDF", ex);
        } finally {
            if (document.isOpen()) {
                document.close();
            }
        }
    }

    // ------------------------------------------------------------------- sections

    private void header(Document document, ReportDTO report) throws DocumentException {
        PdfPTable band = new PdfPTable(new float[]{1f, 4f});
        band.setWidthPercentage(100f);

        PdfPCell logo = new PdfPCell();
        logo.addElement(logoElement());
        logo.setBackgroundColor(PDFUtil.INK);
        logo.setBorder(Rectangle.NO_BORDER);
        logo.setPadding(14f);
        logo.setVerticalAlignment(Element.ALIGN_MIDDLE);
        band.addCell(logo);

        Paragraph title = new Paragraph(AppConstants.PRODUCT_NAME + " - Incident Report", PDFUtil.TITLE);
        Paragraph tagline = new Paragraph(AppConstants.PRODUCT_TAGLINE
                + "  |  " + LogUtil.orDefault(report.classification(), AppConstants.DEFAULT_CLASSIFICATION),
                PDFUtil.SUBTITLE);
        tagline.setSpacingBefore(4f);

        PdfPCell text = new PdfPCell();
        text.addElement(title);
        text.addElement(tagline);
        text.setBackgroundColor(PDFUtil.INK);
        text.setBorder(Rectangle.NO_BORDER);
        text.setPadding(14f);
        text.setVerticalAlignment(Element.ALIGN_MIDDLE);
        band.addCell(text);

        document.add(band);
    }

    /**
     * Company logo placeholder. Drops in {@code src/main/resources/branding/logo.png} when
     * present; otherwise renders a lettermark so the layout never breaks on a fresh
     * deployment.
     */
    private Element logoElement() {
        ClassPathResource resource = new ClassPathResource(LOGO_CLASSPATH);
        if (resource.exists()) {
            try (InputStream in = resource.getInputStream()) {
                Image image = Image.getInstance(in.readAllBytes());
                image.scaleToFit(72f, 48f);
                image.setAlignment(Element.ALIGN_CENTER);
                return image;
            } catch (IOException | DocumentException ex) {
                log.warn("Branding logo present but unreadable, falling back to lettermark: {}", ex.getMessage());
            }
        }
        Paragraph lettermark = new Paragraph("[ ST ]",
                com.lowagie.text.FontFactory.getFont(com.lowagie.text.FontFactory.HELVETICA_BOLD, 20, Color.WHITE));
        lettermark.setAlignment(Element.ALIGN_CENTER);
        return lettermark;
    }

    private void metadata(Document document, ReportDTO report) throws DocumentException {
        PdfPTable table = PDFUtil.table(1.2f, 2.3f, 1.2f, 2.3f);
        table.setSpacingBefore(14f);

        addPair(table, "Incident ID", LogUtil.orDefault(report.incidentCode(),
                String.valueOf(report.incidentId())), false);
        addPair(table, "Report date", DateUtil.full(report.generatedAt()), false);
        addPair(table, "Title", LogUtil.orDefault(report.title(), "-"), true);
        addPair(table, "Severity", report.severity() == null ? "-" : report.severity().name(), true);
        addPair(table, "Risk score", report.riskScore() + " / 100", false);
        addPair(table, "Confidence", report.confidence() + "%", false);
        addPair(table, "Detections", String.valueOf(size(report.threats())), true);
        addPair(table, "Timeline stages", String.valueOf(size(report.timeline())), true);

        document.add(table);
    }

    private void executiveSummary(Document document, ReportDTO report) throws DocumentException {
        document.add(PDFUtil.sectionTitle("Executive summary"));
        document.add(PDFUtil.body(report.summary()));
    }

    private void riskPanel(Document document, ReportDTO report) throws DocumentException {
        PdfPTable panel = PDFUtil.table(1f, 1f, 2f);

        PdfPCell score = new PdfPCell(new Phrase(report.riskScore() + " / 100",
                com.lowagie.text.FontFactory.getFont(com.lowagie.text.FontFactory.HELVETICA_BOLD, 20,
                        PDFUtil.colourFor(report.severity()))));
        score.setPadding(10f);
        score.setBorderColor(PDFUtil.HAIRLINE);
        score.setHorizontalAlignment(Element.ALIGN_CENTER);
        panel.addCell(score);

        PdfPCell severity = new PdfPCell(new Phrase(
                report.severity() == null ? "-" : report.severity().name(),
                com.lowagie.text.FontFactory.getFont(com.lowagie.text.FontFactory.HELVETICA_BOLD, 20,
                        PDFUtil.colourFor(report.severity()))));
        severity.setPadding(10f);
        severity.setBorderColor(PDFUtil.HAIRLINE);
        severity.setHorizontalAlignment(Element.ALIGN_CENTER);
        panel.addCell(severity);

        panel.addCell(PDFUtil.cell(RiskCalculator.label(report.riskScore())
                + ". Correlation confidence " + report.confidence() + "%.", PDFUtil.BODY, true));

        document.add(panel);
    }

    private void threatSummary(Document document, List<ThreatDTO> threats) throws DocumentException {
        document.add(PDFUtil.sectionTitle("Threat summary"));
        if (isEmpty(threats)) {
            document.add(PDFUtil.body("No detections were associated with this incident."));
            return;
        }

        PdfPTable table = PDFUtil.table(0.9f, 2.4f, 0.9f, 1.1f, 1.4f, 0.7f);
        table.addCell(PDFUtil.headerCell("Rule"));
        table.addCell(PDFUtil.headerCell("Detection"));
        table.addCell(PDFUtil.headerCell("Severity"));
        table.addCell(PDFUtil.headerCell("Technique"));
        table.addCell(PDFUtil.headerCell("Host / user"));
        table.addCell(PDFUtil.headerCell("Events"));

        boolean zebra = false;
        for (ThreatDTO threat : threats) {
            table.addCell(PDFUtil.cell(threat.ruleId(), PDFUtil.MONO, zebra));
            table.addCell(PDFUtil.cell(threat.name(), zebra));
            table.addCell(PDFUtil.severityCell(threat.severity(), zebra));
            table.addCell(PDFUtil.cell(threat.mitreTechnique(), PDFUtil.MONO, zebra));
            table.addCell(PDFUtil.cell(LogUtil.orDefault(threat.hostname(), "-")
                    + " / " + LogUtil.orDefault(threat.username(), "-"), zebra));
            table.addCell(PDFUtil.cell(String.valueOf(threat.eventCount()), zebra));
            zebra = !zebra;
        }
        document.add(table);
    }

    private void attackStory(Document document, ReportDTO report) throws DocumentException {
        document.add(PDFUtil.sectionTitle("Attack story"));
        for (String paragraph : LogUtil.orDefault(report.attackStory(),
                "No narrative was generated for this incident.").split("\\R{2,}")) {
            if (!paragraph.isBlank()) {
                document.add(PDFUtil.body(paragraph.trim()));
            }
        }
        if (!LogUtil.isBlank(report.impactAssessment())) {
            document.add(PDFUtil.sectionTitle("Impact assessment"));
            document.add(PDFUtil.body(report.impactAssessment()));
        }
    }

    private void timeline(Document document, List<TimelineDTO> timeline) throws DocumentException {
        document.add(PDFUtil.sectionTitle("Reconstructed timeline"));
        if (isEmpty(timeline)) {
            document.add(PDFUtil.body("No timeline could be reconstructed from the available evidence."));
            return;
        }

        PdfPTable table = PDFUtil.table(0.4f, 0.9f, 2.1f, 1.1f, 0.9f, 3.2f);
        table.addCell(PDFUtil.headerCell("#"));
        table.addCell(PDFUtil.headerCell("Time"));
        table.addCell(PDFUtil.headerCell("Stage"));
        table.addCell(PDFUtil.headerCell("Tactic"));
        table.addCell(PDFUtil.headerCell("Severity"));
        table.addCell(PDFUtil.headerCell("What happened"));

        boolean zebra = false;
        for (TimelineDTO step : timeline) {
            table.addCell(PDFUtil.cell(String.valueOf(step.sequence()), PDFUtil.BODY_BOLD, zebra));
            table.addCell(PDFUtil.cell(LogUtil.orDefault(step.clock(), DateUtil.clock(step.timestamp())),
                    PDFUtil.MONO, zebra));
            table.addCell(PDFUtil.cell(step.stage(), PDFUtil.BODY_BOLD, zebra));
            table.addCell(PDFUtil.cell(step.tactic(), zebra));
            table.addCell(PDFUtil.severityCell(step.severity(), zebra));
            table.addCell(PDFUtil.cell(step.detail(), zebra));
            zebra = !zebra;
        }
        document.add(table);
    }

    private void rootCause(Document document, ReportDTO report) throws DocumentException {
        document.add(PDFUtil.sectionTitle("Root cause"));
        PdfPTable callout = PDFUtil.table(1f);
        PdfPCell cell = new PdfPCell(new Phrase(
                LogUtil.orDefault(report.rootCause(), "Root cause could not be established from the evidence."),
                PDFUtil.BODY_BOLD));
        cell.setPadding(10f);
        cell.setBackgroundColor(new Color(254, 242, 242));
        cell.setBorderColor(new Color(248, 113, 113));
        cell.setBorderWidth(1f);
        callout.addCell(cell);
        document.add(callout);
    }

    private void mitreMapping(Document document, Set<String> techniques, List<ThreatDTO> threats)
            throws DocumentException {
        document.add(PDFUtil.sectionTitle("MITRE ATT&CK mapping"));
        if (isEmpty(threats)) {
            document.add(PDFUtil.body(techniques == null || techniques.isEmpty()
                    ? "No techniques were mapped." : String.join(", ", techniques)));
            return;
        }

        PdfPTable table = PDFUtil.table(1f, 1.4f, 2.6f, 2.4f);
        table.addCell(PDFUtil.headerCell("Technique"));
        table.addCell(PDFUtil.headerCell("Tactic"));
        table.addCell(PDFUtil.headerCell("Technique name"));
        table.addCell(PDFUtil.headerCell("Observed as"));

        boolean zebra = false;
        for (ThreatDTO threat : threats) {
            table.addCell(PDFUtil.cell(threat.mitreTechnique(), PDFUtil.MONO, zebra));
            table.addCell(PDFUtil.cell(threat.mitreTactic(), zebra));
            table.addCell(PDFUtil.cell(threat.mitreTechniqueName(), zebra));
            table.addCell(PDFUtil.cell(threat.name(), zebra));
            zebra = !zebra;
        }
        document.add(table);
    }

    private void affectedAssets(Document document, ReportDTO report) throws DocumentException {
        document.add(PDFUtil.sectionTitle("Affected devices"));
        document.add(PDFUtil.body(joinOrNone(report.affectedHosts(), "No devices were identified.")));

        document.add(PDFUtil.sectionTitle("Affected users"));
        document.add(PDFUtil.body(joinOrNone(report.affectedUsers(), "No accounts were identified.")));
    }

    private void recommendations(Document document, List<RecommendationDTO> recommendations)
            throws DocumentException {
        document.add(PDFUtil.sectionTitle("Recommendations"));
        if (isEmpty(recommendations)) {
            document.add(PDFUtil.body("No remediation actions were proposed."));
            return;
        }

        PdfPTable table = PDFUtil.table(2.2f, 1.2f, 0.9f, 1.2f, 0.7f);
        table.addCell(PDFUtil.headerCell("Action"));
        table.addCell(PDFUtil.headerCell("Target"));
        table.addCell(PDFUtil.headerCell("Priority"));
        table.addCell(PDFUtil.headerCell("Owner"));
        table.addCell(PDFUtil.headerCell("SLA (h)"));

        boolean zebra = false;
        for (RecommendationDTO recommendation : recommendations) {
            table.addCell(PDFUtil.cell(recommendation.action(), PDFUtil.BODY_BOLD, zebra));
            table.addCell(PDFUtil.cell(recommendation.target(), zebra));
            table.addCell(PDFUtil.severityCell(recommendation.priority(), zebra));
            table.addCell(PDFUtil.cell(recommendation.ownerTeam(), zebra));
            table.addCell(PDFUtil.cell(recommendation.slaHours() == null
                    ? "-" : String.valueOf(recommendation.slaHours()), zebra));
            zebra = !zebra;
        }
        document.add(table);

        for (RecommendationDTO recommendation : recommendations) {
            if (!LogUtil.isBlank(recommendation.detail())) {
                document.add(PDFUtil.bullet(recommendation.action() + " - " + recommendation.detail()));
            }
        }
    }

    private void containment(Document document, List<RecommendationDTO> recommendations) throws DocumentException {
        document.add(PDFUtil.sectionTitle("Immediate containment actions"));
        if (isEmpty(recommendations)) {
            document.add(PDFUtil.body("No containment actions were proposed."));
            return;
        }
        int step = 1;
        for (RecommendationDTO recommendation : recommendations.stream()
                .filter(r -> r.priority() != null && r.priority().getWeight() >= 8)
                .toList()) {
            document.add(PDFUtil.bullet(step++ + ". " + recommendation.action()
                    + " (" + LogUtil.orDefault(recommendation.target(), "scope to be confirmed") + ")"));
        }
        if (step == 1) {
            document.add(PDFUtil.body("No action was rated high enough for immediate containment; "
                    + "work the recommendations above in priority order."));
        }
    }

    private void chainOfCustody(Document document, ReportDTO report) throws DocumentException {
        document.add(PDFUtil.sectionTitle("Chain of custody"));
        document.add(PDFUtil.body(LogUtil.orDefault(report.analystNotes(),
                "Generated offline by " + AppConstants.PRODUCT_NAME
                        + ". No evidence left the enclave during analysis.")));
        Paragraph stamp = new Paragraph("Generated " + DateUtil.full(report.generatedAt())
                + " | Incident " + LogUtil.orDefault(report.incidentCode(), "-")
                + " | " + LogUtil.orDefault(report.classification(), AppConstants.DEFAULT_CLASSIFICATION),
                PDFUtil.SMALL);
        stamp.setSpacingBefore(8f);
        document.add(stamp);
    }

    // ------------------------------------------------------------------ internals

    private void addPair(PdfPTable table, String label, String value, boolean zebra) {
        for (PdfPCell cell : PDFUtil.metaRow(label, value, zebra)) {
            table.addCell(cell);
        }
    }

    private String joinOrNone(Set<String> values, String fallback) {
        return values == null || values.isEmpty() ? fallback : String.join(",  ", values);
    }

    private boolean isEmpty(List<?> values) {
        return values == null || values.isEmpty();
    }

    private int size(List<?> values) {
        return values == null ? 0 : values.size();
    }

    /**
     * Page footer: classification marking on the left, page number on the right.
     */
    private static final class FooterEvent extends PdfPageEventHelper {

        private final String classification;
        private final String reference;

        private FooterEvent(ReportDTO report) {
            this.classification = LogUtil.orDefault(report.classification(), AppConstants.DEFAULT_CLASSIFICATION);
            this.reference = LogUtil.orDefault(report.incidentCode(), "AESIOS")
                    + " | " + DateUtil.stamp(report.generatedAt() == null ? Instant.now() : report.generatedAt());
        }

        @Override
        public void onEndPage(PdfWriter writer, Document document) {
            PdfContentByte canvas = writer.getDirectContent();
            float y = document.bottom() - 18f;
            com.lowagie.text.pdf.ColumnText.showTextAligned(canvas, Element.ALIGN_LEFT,
                    new Phrase(classification, PDFUtil.SMALL), document.left(), y, 0);
            com.lowagie.text.pdf.ColumnText.showTextAligned(canvas, Element.ALIGN_CENTER,
                    new Phrase(reference, PDFUtil.SMALL),
                    (document.left() + document.right()) / 2, y, 0);
            com.lowagie.text.pdf.ColumnText.showTextAligned(canvas, Element.ALIGN_RIGHT,
                    new Phrase("Page " + writer.getPageNumber(), PDFUtil.SMALL), document.right(), y, 0);
        }
    }
}
