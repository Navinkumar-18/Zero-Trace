import 'dart:convert';
import 'package:crypto/crypto.dart';
import '../models/partition_info.dart';

/// Service for partition table validation and fingerprint computation.
class PartitionTableService {
  /// Computes canonical SHA-256 partition table fingerprint.
  ///
  /// Canonical format:
  /// Partitions are sorted by ascending partitionNumber.
  /// Each line is formatted as:
  /// "${partitionNumber}:${startSector}:${sizeSectors}\n"
  ///
  /// This matches native Rust zt_engine `compute_partition_table_fingerprint`
  /// and the shared test vector.
  static String computeFingerprint(List<PartitionInfo> partitions) {
    if (partitions.isEmpty) {
      return '';
    }
    final sorted = List<PartitionInfo>.from(partitions)
      ..sort((a, b) => a.partitionNumber.compareTo(b.partitionNumber));

    final buffer = StringBuffer();
    for (final p in sorted) {
      buffer.write('${p.partitionNumber}:${p.startSector}:${p.sizeSectors}\n');
    }
    final canonicalStr = buffer.toString();
    final bytes = utf8.encode(canonicalStr);
    return sha256.convert(bytes).toString();
  }
}
