#!/usr/bin/env python3
"""
Code Analyzer Module

This module contains functions for analyzing code quality, detecting potential bugs,
and suggesting improvements using static analysis techniques.
"""

import ast
import re
from typing import Dict, List, Any
import warnings

class CodeAnalyzer:
    """Main class for analyzing Python code."""
    
    def __init__(self):
        self.issues = []
        self.metrics = {}
        
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze a Python file and return analysis results.
        
        Args:
            file_path: Path to the Python file to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code_content = f.read()
            
            return self.analyze_code(code_content, file_path)
            
        except Exception as e:
            return {
                "error": str(e),
                "file": file_path,
                "issues": [],
                "metrics": {},
                "summary": f"Analysis failed: {e}"
            }
    
    def analyze_code(self, code: str, file_path: str = "unknown") -> Dict[str, Any]:
        """
        Analyze Python code string and return analysis results.
        
        Args:
            code: Python code as string
            file_path: Original file path (for reporting)
            
        Returns:
            Dictionary containing analysis results
        """
        self.issues = []
        self.metrics = {}
        
        # Parse the code
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            self.issues.append({
                "type": "syntax_error",
                "severity": "critical",
                "message": f"Syntax error: {e}",
                "line": e.lineno,
                "column": e.offset
            })
            return self._generate_report(file_path)
        
        # Calculate basic metrics
        self._calculate_metrics(tree, code)
        
        # Run various analyses
        self._check_complexity(tree)
        self._check_naming_conventions(tree)
        self._check_potential_bugs(tree)
        self._check_security_issues(tree)
        self._check_code_style(tree, code)
        
        return self._generate_report(file_path)
    
    def _calculate_metrics(self, tree: ast.AST, code: str) -> None:
        """Calculate code metrics."""
        # Count lines
        lines = code.split('\n')
        self.metrics["total_lines"] = len(lines)
        self.metrics["code_lines"] = len([l for l in lines if l.strip() and not l.strip().startswith('#')])
        self.metrics["comment_lines"] = len([l for l in lines if l.strip().startswith('#')])
        
        # Count functions and classes
        function_count = len([node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)])
        class_count = len([node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)])
        
        self.metrics["function_count"] = function_count
        self.metrics["class_count"] = class_count
        
        # Calculate comment ratio
        if self.metrics["code_lines"] > 0:
            self.metrics["comment_ratio"] = self.metrics["comment_lines"] / self.metrics["code_lines"]
        else:
            self.metrics["comment_ratio"] = 0
    
    def _check_complexity(self, tree: ast.AST) -> None:
        """Check code complexity issues."""
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Check function length
                func_lines = node.end_lineno - node.lineno if node.end_lineno else 0
                if func_lines > 50:
                    self.issues.append({
                        "type": "function_too_long",
                        "severity": "warning",
                        "message": f"Function '{node.name}' is too long ({func_lines} lines). Consider breaking it down.",
                        "line": node.lineno
                    })
                
                # Check parameter count
                arg_count = len(node.args.args) + len(node.args.kwonlyargs)
                if arg_count > 5:
                    self.issues.append({
                        "type": "too_many_parameters",
                        "severity": "warning",
                        "message": f"Function '{node.name}' has {arg_count} parameters. Consider reducing.",
                        "line": node.lineno
                    })
    
    def _check_naming_conventions(self, tree: ast.AST) -> None:
        """Check PEP 8 naming conventions."""
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if not re.match(r'^[a-z_][a-z0-9_]*$', node.name):
                    self.issues.append({
                        "type": "naming_convention",
                        "severity": "info",
                        "message": f"Function name '{node.name}' should use snake_case",
                        "line": node.lineno
                    })
            
            elif isinstance(node, ast.ClassDef):
                if not re.match(r'^[A-Z][a-zA-Z0-9]*$', node.name):
                    self.issues.append({
                        "type": "naming_convention",
                        "severity": "info",
                        "message": f"Class name '{node.name}' should use CamelCase",
                        "line": node.lineno
                    })
    
    def _check_potential_bugs(self, tree: ast.AST) -> None:
        """Check for potential bugs."""
        for node in ast.walk(tree):
            # Check for bare except
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                self.issues.append({
                    "type": "bare_except",
                    "severity": "warning",
                    "message": "Avoid bare except clauses. Specify exception types.",
                    "line": node.lineno
                })
            
            # Check for comparison with None using 'is' or 'is not'
            if isinstance(node, ast.Compare):
                for op in node.ops:
                    if isinstance(op, ast.Eq) or isinstance(op, ast.NotEq):
                        # Check if comparing with None
                        for comparator in node.comparators:
                            if isinstance(comparator, ast.Constant) and comparator.value is None:
                                self.issues.append({
                                    "type": "none_comparison",
                                    "severity": "info",
                                    "message": "Use 'is' or 'is not' for None comparisons, not '==' or '!='",
                                    "line": node.lineno
                                })
    
    def _check_security_issues(self, tree: ast.AST) -> None:
        """Check for security issues."""
        for node in ast.walk(tree):
            # Check for eval usage
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == 'eval':
                    self.issues.append({
                        "type": "security_risk",
                        "severity": "critical",
                        "message": "Avoid using eval() as it can execute arbitrary code",
                        "line": node.lineno
                    })
    
    def _check_code_style(self, tree: ast.AST, code: str) -> None:
        """Check code style issues."""
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            # Check line length
            if len(line) > 79:
                self.issues.append({
                    "type": "line_too_long",
                    "severity": "info",
                    "message": f"Line {i} exceeds 79 characters ({len(line)} chars)",
                    "line": i
                })
            
            # Check for trailing whitespace
            if line.rstrip() != line:
                self.issues.append({
                    "type": "trailing_whitespace",
                    "severity": "info",
                    "message": f"Line {i} has trailing whitespace",
                    "line": i
                })
    
    def _generate_report(self, file_path: str) -> Dict[str, Any]:
        """Generate final analysis report."""
        # Count issues by severity
        severity_counts = {"critical": 0, "warning": 0, "info": 0}
        for issue in self.issues:
            severity_counts[issue["severity"]] += 1
        
        # Generate summary
        total_issues = len(self.issues)
        if total_issues == 0:
            summary = "Code analysis passed with no issues found."
        else:
            summary = f"Found {total_issues} issues: {severity_counts['critical']} critical, {severity_counts['warning']} warnings, {severity_counts['info']} info."
        
        return {
            "file": file_path,
            "issues": self.issues,
            "metrics": self.metrics,
            "severity_counts": severity_counts,
            "summary": summary,
            "timestamp": "2024-01-04T13:51:31Z"  # This would be dynamic in real implementation
        }


def analyze_code(file_path: str) -> Dict[str, Any]:
    """
    Convenience function to analyze a code file.
    
    Args:
        file_path: Path to the code file
        
    Returns:
        Analysis results dictionary
    """
    analyzer = CodeAnalyzer()
    return analyzer.analyze_file(file_path)


if __name__ == "__main__":
    # Example usage
    import sys
    if len(sys.argv) > 1:
        results = analyze_code(sys.argv[1])
        print(f"Analysis results for {sys.argv[1]}:")
        print(f"Summary: {results['summary']}")
        print(f"Metrics: {results['metrics']}")
    else:
        print("Usage: python code_analyzer.py <file_path>")
