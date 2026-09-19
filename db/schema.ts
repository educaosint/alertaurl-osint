import { sql } from "drizzle-orm";
import { integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

export const reportedSites = sqliteTable(
  "reported_sites",
  {
    id: text("id").primaryKey(),
    canonicalUrl: text("canonical_url").notNull(),
    displayUrl: text("display_url").notNull(),
    hostname: text("hostname").notNull(),
    category: text("category").notNull().default("suplantacion"),
    notes: text("notes").notNull().default(""),
    reportCount: integer("report_count").notNull().default(1),
    alertVotes: integer("alert_votes").notNull().default(0),
    disputeVotes: integer("dispute_votes").notNull().default(0),
    status: text("status").notNull().default("community_reported"),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
    updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => ({
    canonicalUrlUnique: uniqueIndex("reported_sites_canonical_url_unique").on(table.canonicalUrl),
  }),
);
