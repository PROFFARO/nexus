"""
ML Logger Module for NEXUS AI Training Pipeline
Provides comprehensive debugging, progress tracking, and verbose output for ML operations.
"""

import logging
import time
import sys
from typing import Dict, List, Any, Optional, Union
from datetime import datetime
from pathlib import Path
import threading

# Try to import colorama for Windows color support
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False


class Colors:
    """ANSI color codes for terminal output"""
    if COLORAMA_AVAILABLE:
        HEADER = Fore.CYAN + Style.BRIGHT
        SUCCESS = Fore.GREEN + Style.BRIGHT
        WARNING = Fore.YELLOW
        ERROR = Fore.RED + Style.BRIGHT
        INFO = Fore.WHITE
        DEBUG = Fore.MAGENTA
        METRIC = Fore.BLUE + Style.BRIGHT
        PHASE = Fore.CYAN
        DATA = Fore.GREEN
        TIMING = Fore.YELLOW
        RESET = Style.RESET_ALL
        BOLD = Style.BRIGHT
        DIM = Style.DIM
    else:
        HEADER = ""
        SUCCESS = ""
        WARNING = ""
        ERROR = ""
        INFO = ""
        DEBUG = ""
        METRIC = ""
        PHASE = ""
        DATA = ""
        TIMING = ""
        RESET = ""
        BOLD = ""
        DIM = ""


class VerbosityLevel:
    """Verbosity level constants"""
    MINIMAL = 0   # Only errors and final results
    NORMAL = 1    # Standard progress updates
    VERBOSE = 2   # Detailed operation info
    DEBUG = 3     # Full debugging output


class MLLogger:
    """
    Comprehensive ML operation logger with rich output.
    
    Provides:
    - Progress tracking with timing information
    - Data statistics display (shapes, sizes, memory)
    - Phase tracking for multi-step operations
    - Formatted metrics output
    - Color-coded severity levels
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, *args, **kwargs):
        """Singleton pattern to ensure consistent logging"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, verbosity: int = VerbosityLevel.NORMAL, service: str = "general"):
        """
        Initialize ML Logger.
        
        Args:
            verbosity: Verbosity level (0-3)
            service: Service type for context (ssh, ftp, mysql)
        """
        if hasattr(self, '_initialized') and self._initialized:
            return
            
        self.verbosity = verbosity
        self.service = service
        self.current_phase = 0
        self.total_phases = 0
        self.phase_start_time = None
        self.operation_start_time = None
        self.timings = {}
        self._initialized = True
        
        # Configure logging
        self.logger = logging.getLogger('nexus.ml')
        
    def set_verbosity(self, level: int):
        """Set verbosity level (0=MINIMAL, 1=NORMAL, 2=VERBOSE, 3=DEBUG)"""
        self.verbosity = max(0, min(3, level))
        
    def set_service(self, service: str):
        """Set current service context"""
        self.service = service
        
    # =========================================================================
    # Banner and Headers
    # =========================================================================
    
    def print_banner(self, title: str, config: Dict[str, Any] = None):
        """Print startup banner with configuration"""
        width = 80
        print(f"\n{Colors.HEADER}{'═' * width}{Colors.RESET}")
        print(f"{Colors.HEADER}🚀 {title}{Colors.RESET}")
        print(f"{Colors.HEADER}{'═' * width}{Colors.RESET}")
        
        if config and self.verbosity >= VerbosityLevel.NORMAL:
            print(f"{Colors.INFO}📅 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
            for key, value in config.items():
                icon = self._get_config_icon(key)
                print(f"{Colors.INFO}{icon} {key}: {value}{Colors.RESET}")
            print(f"{Colors.INFO}📊 Verbosity Level: {self.verbosity} ({self._get_verbosity_name()}){Colors.RESET}")
        
        print(f"{Colors.HEADER}{'═' * width}{Colors.RESET}\n")
        
    def _get_config_icon(self, key: str) -> str:
        """Get icon for configuration key"""
        icons = {
            'datasets': '📂',
            'services': '🎯',
            'algorithms': '🤖',
            'output': '📁',
            'models': '💾',
        }
        return icons.get(key.lower(), '⚙️')
        
    def _get_verbosity_name(self) -> str:
        """Get human-readable verbosity name"""
        names = {0: 'MINIMAL', 1: 'NORMAL', 2: 'VERBOSE', 3: 'DEBUG'}
        return names.get(self.verbosity, 'UNKNOWN')
        
    # =========================================================================
    # Phase Tracking
    # =========================================================================
    
    def start_operation(self, name: str, total_phases: int = 1):
        """Start a new multi-phase operation"""
        self.operation_start_time = time.time()
        self.total_phases = total_phases
        self.current_phase = 0
        self.timings = {}
        
        if self.verbosity >= VerbosityLevel.VERBOSE:
            print(f"\n{Colors.HEADER}▶ Starting: {name} ({total_phases} phases){Colors.RESET}")
            
    def start_phase(self, name: str, total_phases: int = None, current_phase: int = None, description: str = ""):
        """Start a new phase within the operation
        
        Args:
            name: Phase name
            total_phases: Optional total number of phases (for display)
            current_phase: Optional current phase number (for display)
            description: Optional description of the phase
        """
        # Use passed values or increment internal counter
        if current_phase is not None:
            self.current_phase = current_phase
        else:
            self.current_phase += 1
            
        if total_phases is not None:
            self.total_phases = total_phases
            
        self.phase_start_time = time.time()
        
        phase_str = f"[PHASE {self.current_phase}/{self.total_phases}]" if self.total_phases > 1 else "[PHASE]"
        
        print(f"\n{Colors.PHASE}{phase_str} {name}{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 80}{Colors.RESET}")
        
        if description and self.verbosity >= VerbosityLevel.VERBOSE:
            print(f"{Colors.INFO}  {description}{Colors.RESET}")
            
    def end_phase(self, name: str = "", success: bool = True, duration: float = None):
        """End current phase and record timing
        
        Args:
            name: Phase name for timing record
            success: Whether the phase succeeded
            duration: Optional explicit duration (if not provided, calculated from start time)
        """
        if duration is None and self.phase_start_time:
            duration = time.time() - self.phase_start_time
        
        if duration:
            self.timings[name or f"phase_{self.current_phase}"] = duration
            
            if self.verbosity >= VerbosityLevel.VERBOSE:
                status = f"{Colors.SUCCESS}✓" if success else f"{Colors.ERROR}✗"
                print(f"{status} Phase completed in {self._format_duration(duration)}{Colors.RESET}")
                
    def end_operation(self, name: str = "", success: bool = True, duration: float = None):
        """End the current operation and show summary
        
        Args:
            name: Operation name
            success: Whether the operation succeeded
            duration: Optional explicit duration (if not provided, calculated from start time)
        """
        if duration is None and self.operation_start_time:
            total_duration = time.time() - self.operation_start_time
        else:
            total_duration = duration or 0
            
        status_icon = "✅" if success else "❌"
        status_color = Colors.SUCCESS if success else Colors.ERROR
        
        print(f"\n{status_color}{status_icon} {name} completed in {self._format_duration(total_duration)}{Colors.RESET}")
        
        if self.verbosity >= VerbosityLevel.DEBUG and self.timings:
            print(f"\n{Colors.TIMING}⏱️  Phase Timings:{Colors.RESET}")
            for phase, dur in self.timings.items():
                print(f"  {Colors.DIM}├── {phase}: {self._format_duration(dur)}{Colors.RESET}")
                    
    # =========================================================================
    # Progress and Status
    # =========================================================================
    
    def log_step(self, message: str, level: str = "info", indent: int = 1):
        """Log a step within a phase"""
        prefix = "  " * indent
        
        if level == "success":
            print(f"{prefix}{Colors.SUCCESS}✓ {message}{Colors.RESET}")
        elif level == "error":
            print(f"{prefix}{Colors.ERROR}✗ {message}{Colors.RESET}")
        elif level == "warning":
            print(f"{prefix}{Colors.WARNING}⚠ {message}{Colors.RESET}")
        elif level == "debug" and self.verbosity >= VerbosityLevel.DEBUG:
            print(f"{prefix}{Colors.DEBUG}🔍 {message}{Colors.RESET}")
        elif level == "info" and self.verbosity >= VerbosityLevel.NORMAL:
            print(f"{prefix}{Colors.INFO}→ {message}{Colors.RESET}")
        elif level == "data":
            print(f"{prefix}{Colors.DATA}📊 {message}{Colors.RESET}")
            
    def log_progress(self, current: int, total: int, prefix: str = "", 
                     suffix: str = "", bar_length: int = 30):
        """Display a progress bar"""
        if self.verbosity < VerbosityLevel.NORMAL:
            return
            
        percent = current / total if total > 0 else 0
        filled = int(bar_length * percent)
        bar = "█" * filled + "░" * (bar_length - filled)
        
        # Use carriage return for in-place update
        sys.stdout.write(f"\r  {prefix} [{Colors.METRIC}{bar}{Colors.RESET}] {current:,}/{total:,} {suffix}")
        sys.stdout.flush()
        
        if current >= total:
            print()  # New line when complete
            
    def log_file_loaded(self, filename: str, entries: int, size_bytes: int = 0, 
                        cumulative: int = 0):
        """Log file loading with statistics"""
        if self.verbosity < VerbosityLevel.VERBOSE:
            return
            
        size_str = self._format_bytes(size_bytes) if size_bytes else ""
        cumulative_str = f" (Total: {cumulative:,})" if cumulative else ""
        
        print(f"  {Colors.DATA}├── {filename}: {entries:,} entries{cumulative_str} {size_str}{Colors.RESET}")
        
    # =========================================================================
    # Data Statistics
    # =========================================================================
    
    def log_data_stats(self, data: Any, name: str = "Data", indent: int = 1):
        """Display data statistics (shape, size, type)"""
        prefix = "  " * indent
        
        if hasattr(data, 'shape'):
            shape_str = f"Shape: {data.shape}"
            dtype_str = f"dtype: {data.dtype}" if hasattr(data, 'dtype') else ""
            memory = self._estimate_memory(data)
            print(f"{prefix}{Colors.DATA}📊 {name}: {shape_str} | {dtype_str} | {memory}{Colors.RESET}")
        elif isinstance(data, (list, tuple)):
            print(f"{prefix}{Colors.DATA}📊 {name}: {len(data):,} items{Colors.RESET}")
        elif isinstance(data, dict):
            print(f"{prefix}{Colors.DATA}📊 {name}: {len(data):,} keys{Colors.RESET}")
        else:
            print(f"{prefix}{Colors.DATA}📊 {name}: {type(data).__name__}{Colors.RESET}")
            
    def log_feature_transform(self, stage: str, before_shape: tuple, after_shape: tuple):
        """Log feature transformation with shape changes"""
        if self.verbosity < VerbosityLevel.VERBOSE:
            return
            
        print(f"  {Colors.DEBUG}│   ├── {stage}: {before_shape} → {after_shape}{Colors.RESET}")
        
    def log_label_distribution(self, labels: List[str], title: str = "Label Distribution"):
        """Display label distribution"""
        if self.verbosity < VerbosityLevel.VERBOSE:
            return
            
        from collections import Counter
        dist = Counter(labels)
        total = len(labels)
        
        print(f"  {Colors.DATA}📊 {title}:{Colors.RESET}")
        for label, count in sorted(dist.items(), key=lambda x: -x[1]):
            pct = (count / total) * 100
            bar_len = int(pct / 5)
            bar = "█" * bar_len
            print(f"    {Colors.DIM}├── {label}: {count:,} ({pct:.1f}%) {bar}{Colors.RESET}")
            
    # =========================================================================
    # Model and Algorithm Logging
    # =========================================================================
    
    def log_algorithm_start(self, algorithm: str, samples: int = None, service: str = None):
        """Log the start of algorithm training
        
        Args:
            algorithm: Algorithm name
            samples: Optional number of training samples
            service: Optional service context
        """
        svc = service or self.service
        samples_str = f" ({samples:,} samples)" if samples else ""
        print(f"\n  {Colors.METRIC}[ALGO] {algorithm.upper()}{samples_str}{Colors.RESET}")
        return time.time()
        
    def log_algorithm_end(self, algorithm: str, duration: float, 
                          metrics: Dict[str, Any] = None, success: bool = True):
        """Log algorithm training completion with metrics
        
        Args:
            algorithm: Algorithm name
            duration: Training duration in seconds
            metrics: Optional metrics dictionary
            success: Whether training succeeded
        """
        if success:
            print(f"  {Colors.SUCCESS}└── ✓ {algorithm} trained in {self._format_duration(duration)}{Colors.RESET}")
        else:
            print(f"  {Colors.ERROR}└── ✗ {algorithm} failed after {self._format_duration(duration)}{Colors.RESET}")
            
        if metrics and self.verbosity >= VerbosityLevel.NORMAL:
            self.log_metrics(metrics, indent=3)
            
    def log_model_params(self, model_name: str, params: Dict[str, Any]):
        """Log model hyperparameters"""
        if self.verbosity < VerbosityLevel.VERBOSE:
            return
            
        print(f"  {Colors.DEBUG}│   ├── Model: {model_name}{Colors.RESET}")
        for key, value in params.items():
            print(f"  {Colors.DEBUG}│   │   ├── {key}: {value}{Colors.RESET}")
            
    def log_metrics(self, metrics: Dict[str, Any], title: str = "", indent: int = 2):
        """Display formatted metrics"""
        prefix = "  " * indent
        
        if title:
            print(f"{prefix}{Colors.METRIC}📈 {title}{Colors.RESET}")
            
        for key, value in metrics.items():
            if isinstance(value, float):
                print(f"{prefix}{Colors.DIM}├── {key}: {value:.4f}{Colors.RESET}")
            elif isinstance(value, int):
                print(f"{prefix}{Colors.DIM}├── {key}: {value:,}{Colors.RESET}")
            elif isinstance(value, (list, tuple)) and len(value) <= 5:
                print(f"{prefix}{Colors.DIM}├── {key}: {value}{Colors.RESET}")
            else:
                print(f"{prefix}{Colors.DIM}├── {key}: {value}{Colors.RESET}")
                
    # =========================================================================
    # Error and Warning Logging
    # =========================================================================
    
    def log_error(self, message: str, exception: Exception = None, indent: int = 1):
        """Log error with optional exception details"""
        prefix = "  " * indent
        print(f"{prefix}{Colors.ERROR}❌ ERROR: {message}{Colors.RESET}")
        
        if exception and self.verbosity >= VerbosityLevel.DEBUG:
            import traceback
            print(f"{prefix}{Colors.ERROR}   Exception: {type(exception).__name__}: {exception}{Colors.RESET}")
            if self.verbosity >= VerbosityLevel.DEBUG:
                tb = traceback.format_exc()
                for line in tb.split('\n'):
                    print(f"{prefix}{Colors.DIM}   {line}{Colors.RESET}")
                    
    def log_warning(self, message: str, indent: int = 1):
        """Log warning message"""
        prefix = "  " * indent
        print(f"{prefix}{Colors.WARNING}⚠️  WARNING: {message}{Colors.RESET}")
        
    # =========================================================================
    # Embeddings and FAISS Logging
    # =========================================================================
    
    def log_embedding_progress(self, current: int, total: int, cache_hits: int = 0):
        """Log embedding generation progress"""
        if self.verbosity < VerbosityLevel.VERBOSE:
            return
            
        hit_rate = (cache_hits / current * 100) if current > 0 else 0
        self.log_progress(current, total, "Embeddings", f"(Cache: {hit_rate:.1f}%)")
        
    def log_faiss_stats(self, index_size: int, dimension: int, build_time: float):
        """Log FAISS index statistics"""
        print(f"  {Colors.DATA}├── FAISS Index: {index_size:,} vectors × {dimension}D{Colors.RESET}")
        print(f"  {Colors.TIMING}├── Build time: {self._format_duration(build_time)}{Colors.RESET}")
        
    def log_cache_stats(self, hits: int, misses: int, size: int):
        """Log cache statistics"""
        if self.verbosity < VerbosityLevel.VERBOSE:
            return
            
        total = hits + misses
        hit_rate = (hits / total * 100) if total > 0 else 0
        print(f"  {Colors.DATA}├── Cache: {hits:,} hits / {misses:,} misses ({hit_rate:.1f}% hit rate){Colors.RESET}")
        print(f"  {Colors.DATA}├── Cache size: {size:,} entries{Colors.RESET}")
        
    # =========================================================================
    # Summary and Reports
    # =========================================================================
    
    def print_summary(self, results: Dict[str, Any], title: str = "Training Summary"):
        """Print training summary report"""
        width = 80
        print(f"\n{Colors.HEADER}{'═' * width}{Colors.RESET}")
        print(f"{Colors.HEADER}📊 {title}{Colors.RESET}")
        print(f"{Colors.HEADER}{'═' * width}{Colors.RESET}")
        
        for service, result in results.items():
            if result.get('success', False):
                status = f"{Colors.SUCCESS}✅ SUCCESS{Colors.RESET}"
                algorithms = result.get('algorithms_trained', [])
                samples = result.get('training_samples', 0)
                print(f"\n{Colors.DATA}  {service.upper()}: {status}")
                print(f"    ├── Algorithms: {len(algorithms)} trained{Colors.RESET}")
                print(f"    ├── Samples: {samples:,}")
                
                if 'results' in result and self.verbosity >= VerbosityLevel.VERBOSE:
                    for algo, metrics in result.get('results', {}).items():
                        if isinstance(metrics, dict):
                            acc = metrics.get('accuracy', 'N/A')
                            if isinstance(acc, float):
                                print(f"    │   ├── {algo}: {acc:.3f} accuracy")
            else:
                status = f"{Colors.ERROR}❌ FAILED{Colors.RESET}"
                error = result.get('error', 'Unknown error')
                print(f"\n{Colors.ERROR}  {service.upper()}: {status}")
                print(f"    └── Error: {error}{Colors.RESET}")
                
        print(f"\n{Colors.HEADER}{'═' * width}{Colors.RESET}")
    
    def print_training_summary(self, all_results: Dict[str, Dict[str, Any]], total_time: float):
        """Print comprehensive training summary with per-service and per-algorithm results
        
        Args:
            all_results: Dict mapping service -> algorithm -> results
            total_time: Total training time in seconds
        """
        width = 80
        print(f"\n{Colors.HEADER}{'═' * width}{Colors.RESET}")
        print(f"{Colors.HEADER}📊 TRAINING SUMMARY{Colors.RESET}")
        print(f"{Colors.HEADER}{'═' * width}{Colors.RESET}")
        
        total_algorithms = 0
        successful_algorithms = 0
        
        for service, algorithms in all_results.items():
            if not algorithms:
                print(f"\n{Colors.WARNING}  {service.upper()}: No algorithms trained{Colors.RESET}")
                continue
                
            print(f"\n{Colors.DATA}  {service.upper()}{Colors.RESET}")
            
            for algo, result in algorithms.items():
                total_algorithms += 1
                if isinstance(result, dict):
                    accuracy = result.get('accuracy')
                    f1 = result.get('f1_score')
                    auc = result.get('auc_score')
                    train_time = result.get('training_time', 0)
                    
                    if accuracy is not None or f1 is not None or auc is not None:
                        successful_algorithms += 1
                        metrics_parts = []
                        if accuracy is not None:
                            metrics_parts.append(f"acc={accuracy:.3f}")
                        if f1 is not None:
                            metrics_parts.append(f"f1={f1:.3f}")
                        if auc is not None:
                            metrics_parts.append(f"auc={auc:.3f}")
                        metrics_str = ", ".join(metrics_parts)
                        print(f"    {Colors.SUCCESS}✓{Colors.RESET} {algo}: {metrics_str}")
                    else:
                        # Clustering or other models
                        clusters = result.get('n_clusters')
                        if clusters is not None:
                            successful_algorithms += 1
                            print(f"    {Colors.SUCCESS}✓{Colors.RESET} {algo}: {clusters} clusters")
                        else:
                            print(f"    {Colors.WARNING}?{Colors.RESET} {algo}: No metrics available")
        
        # Summary statistics
        print(f"\n{Colors.HEADER}{'─' * width}{Colors.RESET}")
        print(f"{Colors.SUCCESS}✅ Completed: {successful_algorithms}/{total_algorithms} algorithms{Colors.RESET}")
        print(f"{Colors.TIMING}⏱️  Total time: {self._format_duration(total_time)}{Colors.RESET}")
        print(f"{Colors.HEADER}{'═' * width}{Colors.RESET}")
        
    # =========================================================================
    # Utility Methods
    # =========================================================================
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format"""
        if seconds < 1:
            return f"{seconds*1000:.0f}ms"
        elif seconds < 60:
            return f"{seconds:.2f}s"
        elif seconds < 3600:
            mins = int(seconds // 60)
            secs = seconds % 60
            return f"{mins}m {secs:.0f}s"
        else:
            hours = int(seconds // 3600)
            mins = int((seconds % 3600) // 60)
            return f"{hours}h {mins}m"
            
    def _format_bytes(self, size_bytes: int) -> str:
        """Format bytes in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"({size_bytes:.1f} {unit})"
            size_bytes /= 1024
        return f"({size_bytes:.1f} TB)"
        
    def _estimate_memory(self, data) -> str:
        """Estimate memory usage of data"""
        if hasattr(data, 'nbytes'):
            return self._format_bytes(data.nbytes)
        elif hasattr(data, '__sizeof__'):
            return self._format_bytes(data.__sizeof__())
        return ""


# Global logger instance
_ml_logger: Optional[MLLogger] = None


def get_ml_logger(verbosity: int = None, service: str = None) -> MLLogger:
    """Get or create the global ML logger instance"""
    global _ml_logger
    
    if _ml_logger is None:
        _ml_logger = MLLogger(
            verbosity=verbosity or VerbosityLevel.NORMAL,
            service=service or "general"
        )
    else:
        if verbosity is not None:
            _ml_logger.set_verbosity(verbosity)
        if service is not None:
            _ml_logger.set_service(service)
            
    return _ml_logger


def reset_ml_logger():
    """Reset the global ML logger instance"""
    global _ml_logger
    _ml_logger = None
