package com.victor.reconloop;

import burp.api.montoya.MontoyaApi;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.Timer;
import java.awt.BasicStroke;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.geom.Path2D;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/** Paints relationships already held in the host and discovery tables. It never sends a request. */
final class RelationshipGraphPanel extends JPanel {
    private final ReconModel.AssetTableModel assets;
    private final ReconModel.DiscoveryTableModel discoveries;
    private final JTextArea detail = new JTextArea(3, 40);
    private final JLabel legend = new JLabel("A network holds a host, a host exposes a port, and a port serves a script file.");
    private final JLabel summary = new JLabel(" ");
    private final Canvas canvas = new Canvas();
    private RelationshipChart chart = RelationshipChart.build(List.of(), List.of());
    private RelationshipChart.Node selected;
    private double camX = 40;
    private double camY = 40;
    private double scale = 1;
    private final Timer timer = new Timer(32, event -> tick());

    RelationshipGraphPanel(MontoyaApi api, ReconModel.AssetTableModel assets, ReconModel.DiscoveryTableModel discoveries) {
        super(new BorderLayout(6, 6));
        this.assets = assets;
        this.discoveries = discoveries;
        detail.setEditable(false);
        detail.setLineWrap(true);
        detail.setWrapStyleWord(true);
        JButton export = new JButton("Export Meridian JSON");
        export.addActionListener(event -> exportJson());
        JPanel south = new JPanel(new BorderLayout(4, 4));
        south.add(summary, BorderLayout.NORTH);
        south.add(new JScrollPane(detail), BorderLayout.CENTER);
        south.add(export, BorderLayout.EAST);
        add(legend, BorderLayout.NORTH);
        add(canvas, BorderLayout.CENTER);
        add(south, BorderLayout.SOUTH);
        assets.addTableModelListener(event -> rebuild());
        discoveries.addTableModelListener(event -> rebuild());
        rebuild();
        if (api != null) api.userInterface().applyThemeToComponent(this);
    }

    private void tick() {
        if (!chart.step()) timer.stop();
        canvas.repaint();
    }

    private void rebuild() {
        chart = RelationshipChart.build(assets.snapshot(), discoveries.snapshot());
        selected = null;
        detail.setText(chart.empty()
                ? "No relationships yet. Hosts and discovered script files show up here after they are already in scope."
                : "");
        String counts = chart.nodes().stream().filter(node -> node.kind().equals("host")).count() + " hosts · "
                + chart.nodes().stream().filter(node -> node.kind().equals("port")).count() + " ports · "
                + chart.nodes().stream().filter(node -> node.kind().equals("file")).count() + " files";
        summary.setText((chart.notice().isBlank() ? counts : counts + " · " + chart.notice()));
        canvas.fit();
        timer.restart();
    }

    private void exportJson() {
        if (chart.empty()) {
            JOptionPane.showMessageDialog(this, "Nothing to export yet.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Meridian JSON");
        chooser.setSelectedFile(new java.io.File("meridian-burp.json"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        try {
            Files.writeString(chooser.getSelectedFile().toPath(), chart.meridianJson() + "\n");
            JOptionPane.showMessageDialog(this, "Saved\n" + chooser.getSelectedFile());
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, "Save failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void select(RelationshipChart.Node node) {
        selected = node;
        if (node == null) {
            detail.setText("");
            return;
        }
        List<String> ties = new ArrayList<>();
        for (RelationshipChart.Edge edge : chart.edges()) {
            if (edge.source().equals(node.id())) ties.add(edge.verb() + " " + label(edge.target()));
            else if (edge.target().equals(node.id())) ties.add(label(edge.source()) + " " + edge.verb());
        }
        detail.setText(node.kind() + "  " + node.label() + "\n" + node.detail()
                + (ties.isEmpty() ? "" : "\n" + String.join("   ", ties)));
        canvas.repaint();
    }

    private String label(String id) {
        for (RelationshipChart.Node node : chart.nodes()) if (node.id().equals(id)) return node.label();
        return id;
    }

    private final class Canvas extends JPanel {
        private int pressX;
        private int pressY;
        private int lastX;
        private int lastY;
        private String dragId;
        private boolean moved;

        Canvas() {
            setPreferredSize(new Dimension(640, 420));
            setOpaque(true);
            MouseAdapter mouse = new MouseAdapter() {
                @Override public void mousePressed(MouseEvent event) {
                    pressX = lastX = event.getX();
                    pressY = lastY = event.getY();
                    moved = false;
                    RelationshipChart.Body hit = chart.hit(worldX(event.getX()), worldY(event.getY()));
                    dragId = hit == null ? null : hit.node.id();
                }

                @Override public void mouseDragged(MouseEvent event) {
                    int dx = event.getX() - lastX;
                    int dy = event.getY() - lastY;
                    if (dx != 0 || dy != 0) moved = true;
                    if (dragId != null) chart.move(dragId, worldX(event.getX()), worldY(event.getY()));
                    else { camX += dx; camY += dy; }
                    lastX = event.getX();
                    lastY = event.getY();
                    if (!timer.isRunning()) timer.start();
                    repaint();
                }

                @Override public void mouseReleased(MouseEvent event) {
                    if (!moved && Math.hypot(event.getX() - pressX, event.getY() - pressY) < 4) {
                        RelationshipChart.Body hit = chart.hit(worldX(event.getX()), worldY(event.getY()));
                        select(hit == null ? null : hit.node);
                    }
                    dragId = null;
                }

                @Override public void mouseWheelMoved(java.awt.event.MouseWheelEvent event) {
                    double worldX = worldX(event.getX());
                    double worldY = worldY(event.getY());
                    scale = Math.max(0.35, Math.min(2.8, scale * (event.getWheelRotation() < 0 ? 1.12 : 0.89)));
                    camX = event.getX() - worldX * scale;
                    camY = event.getY() - worldY * scale;
                    repaint();
                }
            };
            addMouseListener(mouse);
            addMouseMotionListener(mouse);
            addMouseWheelListener(mouse);
        }

        void fit() {
            if (chart.bodies().isEmpty()) { camX = 24; camY = 24; scale = 1; repaint(); return; }
            double minX = Double.POSITIVE_INFINITY, minY = minX, maxX = Double.NEGATIVE_INFINITY, maxY = maxX;
            for (RelationshipChart.Body body : chart.bodies()) {
                minX = Math.min(minX, body.x); maxX = Math.max(maxX, body.x);
                minY = Math.min(minY, body.y); maxY = Math.max(maxY, body.y);
            }
            int width = Math.max(getWidth(), 640);
            int height = Math.max(getHeight(), 420);
            double span = Math.max(80, Math.max(maxX - minX, maxY - minY));
            scale = Math.max(0.35, Math.min(2.2, Math.min(width, height) / (span + 120)));
            camX = width / 2.0 - ((minX + maxX) / 2) * scale;
            camY = height / 2.0 - ((minY + maxY) / 2) * scale;
            repaint();
        }

        @Override protected void paintComponent(Graphics graphics) {
            super.paintComponent(graphics);
            Graphics2D g = (Graphics2D) graphics.create();
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            Color ink = getForeground();
            boolean dark = ink.getRed() + ink.getGreen() + ink.getBlue() > 380;
            g.setFont(getFont().deriveFont((float) Math.max(10, 12 / scale)));
            g.translate(camX, camY);
            g.scale(scale, scale);
            g.setStroke(new BasicStroke((float) (1.2 / scale)));
            for (RelationshipChart.Edge edge : chart.edges()) {
                RelationshipChart.Body a = body(edge.source());
                RelationshipChart.Body b = body(edge.target());
                if (a == null || b == null) continue;
                boolean hot = selected != null && (selected.id().equals(edge.source()) || selected.id().equals(edge.target()));
                g.setColor(hot ? new Color(196, 154, 74) : new Color(ink.getRed(), ink.getGreen(), ink.getBlue(), dark ? 120 : 80));
                g.drawLine((int) a.x, (int) a.y, (int) b.x, (int) b.y);
            }
            for (RelationshipChart.Body body : chart.bodies()) {
                boolean hot = selected != null && selected.id().equals(body.node.id());
                g.setColor(color(body.node.kind(), hot));
                g.fill(shapeOf(body));
                if (hot) {
                    g.setColor(new Color(196, 154, 74));
                    g.draw(shapeOf(body));
                }
                g.setColor(ink);
                g.drawString(body.node.label(), (float) (body.x + 10), (float) (body.y - 8));
            }
            g.dispose();
        }

        private RelationshipChart.Body body(String id) {
            for (RelationshipChart.Body body : chart.bodies()) if (body.node.id().equals(id)) return body;
            return null;
        }

        private Path2D shapeOf(RelationshipChart.Body body) {
            double x = body.x;
            double y = body.y;
            double r = 7;
            Path2D path = new Path2D.Double();
            switch (body.node.kind()) {
                case "net" -> {
                    for (int i = 0; i < 6; i++) {
                        double a = Math.PI / 3 * i - Math.PI / 6;
                        double px = x + Math.cos(a) * r;
                        double py = y + Math.sin(a) * r;
                        if (i == 0) path.moveTo(px, py); else path.lineTo(px, py);
                    }
                    path.closePath();
                }
                case "file" -> {
                    path.moveTo(x - r, y - r);
                    path.lineTo(x + r * 0.3, y - r);
                    path.lineTo(x + r, y - r * 0.3);
                    path.lineTo(x + r, y + r);
                    path.lineTo(x - r, y + r);
                    path.closePath();
                }
                case "port" -> path.append(new java.awt.geom.Ellipse2D.Double(x - r, y - r, r * 2, r * 2), false);
                default -> path.append(new java.awt.geom.Ellipse2D.Double(x - r * 0.9, y - r * 0.9, r * 1.8, r * 1.8), false);
            }
            return path;
        }

        private Color color(String kind, boolean hot) {
            if (hot) return new Color(196, 154, 74);
            return switch (kind) {
                case "net" -> new Color(184, 148, 74);
                case "host" -> new Color(110, 150, 118);
                case "file" -> new Color(232, 224, 208);
                default -> new Color(210, 206, 196);
            };
        }

        private double worldX(int x) { return (x - camX) / scale; }
        private double worldY(int y) { return (y - camY) / scale; }
    }
}
