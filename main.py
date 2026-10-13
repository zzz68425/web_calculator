"""
主程式入口
"""

import argparse
import sys

from config import Config
from utils.logger import get_logger
from website_finder import WebsiteFinder

logger = get_logger("main")


def main():
    """主函數"""
    parser = argparse.ArgumentParser(
        description='Shodan + VirusTotal 網站發現工具'
    )
    parser.add_argument(
        'cert_pattern',
        nargs='?',
        help='憑證模式 (例如: *.ptivs.tn.edu.tw)'
    )
    parser.add_argument(
        '--shodan-key',
        help='Shodan API Key',
        default=None
    )
    parser.add_argument(
        '--vt-key',
        help='VirusTotal API Key (單一 key 或逗號分隔多 key)',
        default=None
    )
    parser.add_argument(
        '--db-path',
        help='資料庫路徑',
        default='website.db'
    )
    parser.add_argument(
        '--quick',
        action='store_true',
        help='快速模式：限制查詢數量進行測試'
    )
    
    args = parser.parse_args()
    
    # 建立配置
    config = Config.from_env()
    
    # 覆寫 API Keys（如果有提供）
    if args.shodan_key:
        config.SHODAN_API_KEY = args.shodan_key.strip()
    if args.vt_key:
        # 允許多組 key 以逗號輸入
        from config import _parse_vt_multi  # 重用解析
        config.VIRUSTOTAL_API_KEYS = _parse_vt_multi(args.vt_key)
    if args.db_path:
        config.DATABASE_PATH = args.db_path
    
    # 驗證配置
    try:
        config.validate()
    except ValueError as e:
        logger.error(f"配置錯誤: {e}")
        logger.info("請設定環境變數或使用命令列參數提供 API Keys")
        sys.exit(1)
    
    # 取得憑證模式
    if not args.cert_pattern:
        print("請輸入要搜尋的憑證模式 (例如: *.ptivs.tn.edu.tw)")
        cert_pattern = input("憑證模式: ").strip()
        if not cert_pattern:
            logger.error("請輸入有效的憑證模式")
            sys.exit(1)
    else:
        cert_pattern = args.cert_pattern
    
    # 選擇查詢模式
    print("\n請選擇查詢模式:")
    print("  1. Shodan + xlsx 合併查詢（完整模式）")
    print("  2. 只查詢 Shodan 結果（跳過 xlsx）")
    print("  3. 從上次中斷處繼續")
    mode_input = input("請輸入模式 (1、2 或 3，預設 1): ").strip()
    skip_xlsx = (mode_input == "2")
    resume = (mode_input == "3")
    
    # 執行搜尋
    try:
        finder = WebsiteFinder(config)
        if args.quick:
            logger.info("快速模式啟用：將限制查詢範圍進行測試")
        results = finder.run(cert_pattern, quick_mode=args.quick, skip_xlsx=skip_xlsx, resume=resume)
        
        if results:
            logger.info(f"\n搜尋完成！找到 {len(results)} 個網站")
        else:
            logger.info("\n搜尋完成，但沒有找到可用的網站")
            
    except KeyboardInterrupt:
        print("\n\n程式已被使用者中斷")
        logger.info("使用者中斷程式")
        sys.exit(0)
    except Exception as e:
        logger.error(f"程式執行錯誤: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
