#!/usr/bin/env python3
"""
AI Code Reviewer - Main Entry Point

This module serves as the main entry point for the AI Code Reviewer application.
It orchestrates the code analysis pipeline and handles user interactions.
"""

import argparse
import sys
from pathlib import Path

from code_analyzer import analyze_code
from report_generator import generate_report
from utils.logger import setup_logger

def main():
    """Main function to run the AI Code Reviewer."""
    parser = argparse.ArgumentParser(description='AI Code Reviewer - Analyze code quality and suggest improvements')
    parser.add_argument('file_path', help='Path to the code file to analyze')
    parser.add_argument('--output', '-o', default='report.md', help='Output report file path')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Setup logger
    logger = setup_logger(verbose=args.verbose)
    
    # Check if file exists
    if not Path(args.file_path).exists():
        logger.error(f"File not found: {args.file_path}")
        sys.exit(1)
    
    logger.info(f"Analyzing code file: {args.file_path}")
    
    try:
        # Analyze the code
        analysis_results = analyze_code(args.file_path)
        
        # Generate report
        generate_report(analysis_results, args.output)
        
        logger.info(f"Analysis complete. Report saved to: {args.output}")
        logger.info(f"Summary: {analysis_results.get('summary', 'No summary available')}")
        
    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
