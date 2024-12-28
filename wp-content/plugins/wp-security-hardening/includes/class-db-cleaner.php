<?php
if (!defined('ABSPATH')) {
    die('Direct access not permitted.');
}

class WP_Security_DB_Cleaner {
    private $last_cleanup_option = 'wp_security_last_db_cleanup';
    
    public function __construct() {
        add_action('wp_security_daily_cleanup', array($this, 'cleanup'));
    }

    public function cleanup() {
        global $wpdb;
        
        $start_time = time();
        $cleaned = array();
        
        // Start transaction
        $wpdb->query('START TRANSACTION');
        
        try {
            // 1. Post revisions
            $cleaned['revisions'] = $this->clean_revisions();

            // 2. Auto-drafts
            $cleaned['auto_drafts'] = $this->clean_auto_drafts();

            // 3. Trashed posts
            $cleaned['trash'] = $this->clean_trash();

            // 4. Orphaned post meta
            $cleaned['orphaned_meta'] = $this->clean_orphaned_meta();

            // 5. Orphaned term relationships
            $cleaned['orphaned_relationships'] = $this->clean_orphaned_relationships();

            // 6. Expired transients
            $cleaned['transients'] = $this->clean_transients();

            // 7. Spam comments
            $cleaned['spam'] = $this->clean_spam();

            // 8. Unused terms
            $cleaned['unused_terms'] = $this->clean_unused_terms();

            // 9. Optimize tables
            $this->optimize_tables();

            $wpdb->query('COMMIT');
        } catch (Exception $e) {
            $wpdb->query('ROLLBACK');
            error_log('DB Cleanup failed: ' . $e->getMessage());
            return false;
        }

        update_option($this->last_cleanup_option, array(
            'time' => $start_time,
            'results' => $cleaned
        ));

        return $cleaned;
    }

    private function clean_revisions() {
        global $wpdb;
        
        $query = "DELETE FROM $wpdb->posts WHERE post_type = 'revision'";
        return $wpdb->query($query);
    }

    private function clean_auto_drafts() {
        global $wpdb;
        
        $query = $wpdb->prepare(
            "DELETE FROM $wpdb->posts WHERE post_status = 'auto-draft' 
             OR (post_status = 'draft' AND post_modified < %s)",
            date('Y-m-d', strtotime('-30 days'))
        );
        
        return $wpdb->query($query);
    }

    private function clean_trash() {
        global $wpdb;
        
        $query = $wpdb->prepare(
            "DELETE FROM $wpdb->posts WHERE post_status = 'trash' 
             AND post_modified < %s",
            date('Y-m-d', strtotime('-30 days'))
        );
        
        return $wpdb->query($query);
    }

    private function clean_orphaned_meta() {
        global $wpdb;
        
        $query = "DELETE pm FROM $wpdb->postmeta pm 
                 LEFT JOIN $wpdb->posts p ON p.ID = pm.post_id 
                 WHERE p.ID IS NULL";
        
        return $wpdb->query($query);
    }

    private function clean_orphaned_relationships() {
        global $wpdb;
        
        $query = "DELETE tr FROM $wpdb->term_relationships tr 
                 LEFT JOIN $wpdb->posts p ON p.ID = tr.object_id 
                 WHERE p.ID IS NULL";
        
        return $wpdb->query($query);
    }

    private function clean_transients() {
        global $wpdb;
        
        $time = time();
        $query = $wpdb->prepare(
            "DELETE FROM $wpdb->options 
             WHERE option_name LIKE %s 
             AND option_value < %d",
            $wpdb->esc_like('_transient_timeout_') . '%',
            $time
        );
        
        $wpdb->query($query);
        
        $query = $wpdb->prepare(
            "DELETE FROM $wpdb->options 
             WHERE option_name LIKE %s",
            $wpdb->esc_like('_transient_') . '%'
        );
        
        return $wpdb->query($query);
    }

    private function clean_spam() {
        global $wpdb;
        
        $query = "DELETE FROM $wpdb->comments WHERE comment_approved = 'spam'";
        return $wpdb->query($query);
    }

    private function clean_unused_terms() {
        global $wpdb;
        
        // Remove unused terms
        $query = "DELETE t, tt FROM $wpdb->terms t 
                 LEFT JOIN $wpdb->term_taxonomy tt ON t.term_id = tt.term_id 
                 LEFT JOIN $wpdb->term_relationships tr ON tt.term_taxonomy_id = tr.term_taxonomy_id 
                 WHERE tr.object_id IS NULL";
        
        return $wpdb->query($query);
    }

    private function optimize_tables() {
        global $wpdb;
        
        $tables = $wpdb->get_col("SHOW TABLES LIKE '{$wpdb->prefix}%'");
        
        foreach ($tables as $table) {
            $wpdb->query("OPTIMIZE TABLE $table");
        }
    }

    public function get_db_stats() {
        global $wpdb;
        
        $stats = array();
        
        // Get table sizes
        $tables = $wpdb->get_results("SHOW TABLE STATUS LIKE '{$wpdb->prefix}%'");
        
        $total_size = 0;
        $total_overhead = 0;
        
        foreach ($tables as $table) {
            $size = ($table->Data_length + $table->Index_length);
            $total_size += $size;
            
            if ($table->Data_free > 0) {
                $total_overhead += $table->Data_free;
            }
            
            $stats['tables'][] = array(
                'name' => $table->Name,
                'rows' => $table->Rows,
                'size' => size_format($size),
                'overhead' => size_format($table->Data_free)
            );
        }
        
        $stats['total_size'] = size_format($total_size);
        $stats['total_overhead'] = size_format($total_overhead);
        
        // Get counts of cleanup-able items
        $stats['cleanup_potential'] = array(
            'revisions' => $wpdb->get_var(
                "SELECT COUNT(*) FROM $wpdb->posts WHERE post_type = 'revision'"
            ),
            'auto_drafts' => $wpdb->get_var(
                "SELECT COUNT(*) FROM $wpdb->posts WHERE post_status = 'auto-draft'"
            ),
            'trash' => $wpdb->get_var(
                "SELECT COUNT(*) FROM $wpdb->posts WHERE post_status = 'trash'"
            ),
            'spam' => $wpdb->get_var(
                "SELECT COUNT(*) FROM $wpdb->comments WHERE comment_approved = 'spam'"
            )
        );
        
        return $stats;
    }

    public function get_last_cleanup() {
        return get_option($this->last_cleanup_option);
    }
}
