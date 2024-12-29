<?php
/**
 * VirusTotal Scanner
 * Handles file scanning using VirusTotal API with efficient batching
 */
class WP_Security_VirusTotal_Scanner {
	private $api_key;
	private $resource_monitor;

	public function __construct() {
		$this->api_key          = defined( 'VIRUSTOTAL_API_KEY' ) ? VIRUSTOTAL_API_KEY : get_option( 'wp_security_virustotal_key' );
		$this->resource_monitor = WP_Security_Hardening::get_instance()->get_resource_monitor();
	}

	/**
	 * Scan files efficiently in batches
	 */
	public function scan_files( $files ) {
		if ( empty( $this->api_key ) ) {
			return array( 'error' => 'VirusTotal API key not configured' );
		}

		$results  = array();
		$batch_id = $this->resource_monitor->queue_for_scan( $files );

		if ( ! $batch_id ) {
			return $results; // Files already verified or no API calls available
		}

		while ( $batch = $this->resource_monitor->get_scan_batch( $batch_id ) ) {
			// Process batch
			$batch_results = $this->process_batch( $batch );
			$results       = array_merge( $results, $batch_results );

			// Mark clean files
			$clean_files = array_filter(
				$batch,
				function ( $file ) use ( $batch_results ) {
					return empty( $batch_results[ $file ]['threats'] );
				}
			);
			$this->resource_monitor->mark_files_verified( $clean_files );
		}

		return $results;
	}

	/**
	 * Process a batch of files
	 */
	private function process_batch( $files ) {
		$results = array();
		$hashes  = array();

		// Get file hashes
		foreach ( $files as $file ) {
			$hash            = hash_file( 'sha256', $file );
			$hashes[ $hash ] = $file;
		}

		// Check existing reports first
		$existing = $this->check_reports( array_keys( $hashes ) );
		foreach ( $existing as $hash => $report ) {
			if ( $report ) {
				$file             = $hashes[ $hash ];
				$results[ $file ] = $this->parse_report( $report );
				unset( $hashes[ $hash ] );
			}
		}

		// Upload remaining files
		if ( ! empty( $hashes ) ) {
			$upload_results = $this->upload_files( array_values( $hashes ) );
			foreach ( $upload_results as $file => $report ) {
				$results[ $file ] = $this->parse_report( $report );
			}
		}

		$this->resource_monitor->log_api_call();
		return $results;
	}

	/**
	 * Check existing reports
	 */
	private function check_reports( $hashes ) {
		$url     = 'https://www.virustotal.com/vtapi/v2/file/report';
		$reports = array();

		$response = wp_remote_post(
			$url,
			array(
				'body' => array(
					'apikey'   => $this->api_key,
					'resource' => implode( ',', $hashes ),
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return array();
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! empty( $body ) ) {
			foreach ( $hashes as $hash ) {
				$reports[ $hash ] = $body[ $hash ] ?? null;
			}
		}

		return $reports;
	}

	/**
	 * Upload files for scanning
	 */
	private function upload_files( $files ) {
		$url     = 'https://www.virustotal.com/vtapi/v2/file/scan';
		$results = array();

		foreach ( $files as $file ) {
			if ( ! file_exists( $file ) ) {
				continue;
			}

			$response = wp_remote_post(
				$url,
				array(
					'headers' => array(
						'Content-Type' => 'multipart/form-data',
					),
					'body'    => array(
						'apikey' => $this->api_key,
						'file'   => file_get_contents( $file ),
					),
				)
			);

			if ( ! is_wp_error( $response ) ) {
				$body = json_decode( wp_remote_retrieve_body( $response ), true );
				if ( ! empty( $body['scan_id'] ) ) {
					// Wait for results
					sleep( 15 ); // VirusTotal needs time to process
					$results[ $file ] = $this->get_report( $body['scan_id'] );
				}
			}
		}

		return $results;
	}

	/**
	 * Get scan report
	 */
	private function get_report( $scan_id ) {
		$url = 'https://www.virustotal.com/vtapi/v2/file/report';

		$response = wp_remote_post(
			$url,
			array(
				'body' => array(
					'apikey'   => $this->api_key,
					'resource' => $scan_id,
				),
			)
		);

		if ( ! is_wp_error( $response ) ) {
			return json_decode( wp_remote_retrieve_body( $response ), true );
		}

		return null;
	}

	/**
	 * Parse VirusTotal report
	 */
	private function parse_report( $report ) {
		if ( empty( $report ) || $report['response_code'] === 0 ) {
			return array( 'status' => 'clean' );
		}

		$threats = array();

		// Check antivirus results
		if ( ! empty( $report['scans'] ) ) {
			foreach ( $report['scans'] as $av => $result ) {
				if ( $result['detected'] ) {
					$threats[] = array(
						'type'   => 'antivirus',
						'engine' => $av,
						'name'   => $result['result'],
					);
				}
			}
		}

		// Check YARA rules matches
		if ( ! empty( $report['additional_info']['yara'] ) ) {
			foreach ( $report['additional_info']['yara'] as $rule ) {
				$threats[] = array(
					'type'        => 'yara',
					'rule'        => $rule['name'],
					'description' => $rule['description'] ?? '',
				);
			}
		}

		return array(
			'status'  => empty( $threats ) ? 'clean' : 'infected',
			'threats' => $threats,
		);
	}
}
