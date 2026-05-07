#!/usr/bin/env node
import fs from 'fs/promises';
import path from 'path';
import yaml from 'yaml';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function loadYamlConfig() {
    const configPath = path.join(__dirname, 'config', 'detection_rules.yaml');
    const content = await fs.readFile(configPath, 'utf8');
    return yaml.parse(content);
}

async function debugWeakCryptoRule() {
    const config = await loadYamlConfig();
    
    console.log('=== 配置文件根结构 ===');
    console.log(Object.keys(config));
    console.log();
    
    const rule = config.detectionRules.weak_crypto;
    
    if (!rule) {
        console.log('❌ 未找到 weak_crypto 规则');
        console.log('detectionRules 中的规则:', Object.keys(config.detectionRules));
        return;
    }
    
    console.log('=== 规则详情 ===');
    console.log('规则ID: weak_crypto');
    console.log('描述:', rule.description);
    console.log('Java 规则详情:');
    console.log('风险模式:', rule.languages.java.riskPatterns);
    console.log();
    
    const testCode = 'Cipher cipher = Cipher.getInstance("DES");';
    console.log('=== 测试代码 ===');
    console.log(testCode);
    console.log();
    
    console.log('=== 正则匹配测试 ===');
    for (const p of rule.languages.java.riskPatterns) {
        try {
            const regex = new RegExp(p.pattern);
            const match = regex.test(testCode);
            console.log(`模式: ${p.pattern}`);
            console.log(`是否匹配: ${match}`);
            if (match) {
                console.log('匹配结果:', testCode.match(regex));
            }
            console.log();
        } catch (e) {
            console.error(`正则错误: ${p.pattern}`);
            console.error(e);
            console.log();
        }
    }
}

debugWeakCryptoRule();
