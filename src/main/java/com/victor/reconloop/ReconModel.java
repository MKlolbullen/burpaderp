package com.victor.reconloop;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

final class ReconModel {
    record FindingRow(String severity, String provider, String rule, String location, String value, String url) {}
    record DiscoveryRow(String kind, String url, String source) {}
    record ParameterRow(int score, String type, String name, String classes, String value, String url) {}
    record ReflectionRow(String severity, String parameter, String type, String context,
                         String surviving, String suggestion, String value, String url) {}
    record ActiveRow(String severity, String testClass, String parameter, String status,
                     String evidence, String url) {}

    static final class FindingTableModel extends AbstractTableModel {
        private final String[] columns = {"Severity", "Provider", "Rule", "Location", "Value", "URL"};
        private final List<FindingRow> rows = new ArrayList<>();
        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }
        @Override public Object getValueAt(int row, int col) {
            FindingRow r = rows.get(row);
            return switch (col) {
                case 0 -> r.severity(); case 1 -> r.provider(); case 2 -> r.rule();
                case 3 -> r.location(); case 4 -> r.value(); default -> r.url();
            };
        }
        void add(FindingRow row) { rows.add(0, row); fireTableRowsInserted(0, 0); }
        void clear() { int n = rows.size(); rows.clear(); if (n > 0) fireTableDataChanged(); }
    }

    static final class DiscoveryTableModel extends AbstractTableModel {
        private final String[] columns = {"Type", "URL", "Discovered from"};
        private final List<DiscoveryRow> rows = new ArrayList<>();
        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }
        @Override public Object getValueAt(int row, int col) {
            DiscoveryRow r = rows.get(row);
            return switch (col) { case 0 -> r.kind(); case 1 -> r.url(); default -> r.source(); };
        }
        void add(DiscoveryRow row) { rows.add(0, row); fireTableRowsInserted(0, 0); }
        void clear() { int n = rows.size(); rows.clear(); if (n > 0) fireTableDataChanged(); }
    }

    static final class ParameterTableModel extends AbstractTableModel {
        private final String[] columns = {"Score", "Type", "Parameter", "Candidate classes", "Value preview", "URL"};
        private final List<ParameterRow> rows = new ArrayList<>();
        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }
        @Override public Object getValueAt(int row, int col) {
            ParameterRow r = rows.get(row);
            return switch (col) {
                case 0 -> r.score(); case 1 -> r.type(); case 2 -> r.name();
                case 3 -> r.classes(); case 4 -> r.value(); default -> r.url();
            };
        }
        void add(ParameterRow row) { rows.add(0, row); fireTableRowsInserted(0, 0); }
        void clear() { int n = rows.size(); rows.clear(); if (n > 0) fireTableDataChanged(); }
    }

    static final class ReflectionTableModel extends AbstractTableModel {
        private final String[] columns = {"Severity", "Parameter", "Type", "Reflection context", "Surviving", "Suggested vector", "Value", "URL"};
        private final List<ReflectionRow> rows = new ArrayList<>();
        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }
        @Override public Object getValueAt(int row, int col) {
            ReflectionRow r = rows.get(row);
            return switch (col) {
                case 0 -> r.severity(); case 1 -> r.parameter(); case 2 -> r.type();
                case 3 -> r.context(); case 4 -> r.surviving(); case 5 -> r.suggestion();
                case 6 -> r.value(); default -> r.url();
            };
        }
        void add(ReflectionRow row) { rows.add(0, row); fireTableRowsInserted(0, 0); }
        void clear() { int n = rows.size(); rows.clear(); if (n > 0) fireTableDataChanged(); }
    }

    static final class ActiveTableModel extends AbstractTableModel {
        private final String[] columns = {"Severity", "Class", "Parameter", "Status", "Evidence", "URL"};
        private final List<ActiveRow> rows = new ArrayList<>();
        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }
        @Override public Object getValueAt(int row, int col) {
            ActiveRow r = rows.get(row);
            return switch (col) {
                case 0 -> r.severity(); case 1 -> r.testClass(); case 2 -> r.parameter();
                case 3 -> r.status(); case 4 -> r.evidence(); default -> r.url();
            };
        }
        void add(ActiveRow row) { rows.add(0, row); fireTableRowsInserted(0, 0); }
        void clear() { int n = rows.size(); rows.clear(); if (n > 0) fireTableDataChanged(); }
    }
}
