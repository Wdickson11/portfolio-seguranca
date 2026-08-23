---
layout: post
title: "Monitoramento de Ameaças e Resposta Automática em APIs na AWS"
date: 2025-08-09
categories: [Cloud Security, Serverless, AWS]
tags: [AWS, API Gateway, Lambda, WAF, CloudWatch, SNS]
description: "Camada de segurança serverless que inspeciona tráfego de APIs em tempo real, bloqueia requisições maliciosas e alerta o time de segurança automaticamente."
---


![Category](https://img.shields.io/badge/Category-Cloud_Security-blue)
![Focus](https://img.shields.io/badge/Focus-Serverless_Automation-success)
![Stack](https://img.shields.io/badge/Stack-AWS-orange)

Camada de segurança serverless que inspeciona o tráfego de APIs em tempo real, bloqueia requisições maliciosas de forma dinâmica e alerta o time de segurança automaticamente — construída para fechar uma lacuna identificada em uma auditoria de segurança de terceiros (APIs sem monitoramento e sem proteção, lidando com dados sensíveis).

## Problema

APIs são a principal superfície de integração entre sistemas internos e externos, mas também são uma superfície de ataque crescente: vazamento de dados, tentativas de DoS e nenhuma visibilidade centralizada sobre tráfego, abuso ou postura de compliance (LGPD / PCI DSS). Uma auditoria interna apontou essa lacuna diretamente — sem monitoramento, sem resposta automatizada, sem trilha auditável.

## Arquitetura

```
Cliente → API Gateway (REST, regional) → Lambda (MonitoramentoAPI)
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    ▼                         ▼                         ▼
              AWS WAF (Web ACL)         Amazon SNS               Amazon CloudWatch
         IP Set dinâmico + regras     alertas em tempo real    logs centralizados, métricas
         gerenciadas (SQLi, XSS,      para o time de           customizadas, alarmes (picos
         rate limit 2000 req/5min)    segurança (e-mail)       5xx, taxa de bloqueio WAF, erros Lambda)
```

**Fluxo:** toda requisição passa pelo API Gateway → a Lambda inspeciona IP de origem, User-Agent, path e payload → se um padrão malicioso é detectado (IP conhecido, User-Agent malicioso, payload típico de SQLi), a Lambda atualiza o IP Set do WAF em tempo real, bloqueando essa origem para todas as requisições futuras, e publica um alerta via SNS. Todo evento — limpo ou bloqueado — é registrado no CloudWatch para rastreabilidade total.

## O que foi implementado

- **API Gateway (REST, regional)** — endpoint público, integração via Lambda Proxy para passagem completa dos detalhes do evento HTTP.
- **Lambda (`MonitoramentoAPI`, Python 3.13)** — inspeciona cada requisição, executa verificações de threat intelligence (padrões suspeitos de IP / User-Agent / payload), aciona atualizações no WAF e alertas via SNS. Retorna 403 em caso de bloqueio, 200 em caso normal e 500 em exceção controlada. Configurações (região do WAF, ID do IP Set, ARN do tópico SNS) são externalizadas via variáveis de ambiente — sem valores fixos no código.
- **AWS WAF (Web ACL, regional)** — regras gerenciadas da AWS (Common Rule Set, SQLi, Admin Protection) + regra customizada de rate limiting (2.000 requisições / 5 min por IP de origem) + IP Set dinâmico atualizado programaticamente pela Lambda.
- **CloudWatch** — grupos de log dedicados por endpoint, métricas customizadas para contagem de erros e latência, consultas via Logs Insights para correlação de eventos, e alarmes para: picos de erro 5xx, alta taxa de bloqueio no WAF e erros de execução da Lambda.
- **SNS** — tópico de alerta integrado aos alarmes do CloudWatch e diretamente ao fluxo de detecção da Lambda, notificando o time de segurança por e-mail quase em tempo real.

## Validação

Em vez de apenas descrever o design, executei simulações controladas de ataque contra o stack implantado para comprovar que a resposta automatizada realmente funciona:

**Tentativa de SQL injection, antes das regras do WAF ativas:**
```
$ curl -X POST https://<api-id>.execute-api.us-east-1.amazonaws.com/default/monitoramento \
    -d "id=1' OR '1'='1" --ssl-no-revoke
{"message": "API chamada com sucesso", "log": {...}}   # requisição passou
```

**Mesma requisição, com regras gerenciadas do WAF + proteção customizada contra SQLi ativas:**
```
$ curl -X POST https://<api-id>.execute-api.us-east-1.amazonaws.com/default/monitoramento \
    -d "id=1' OR '1'='1" --ssl-no-revoke
{"message": "Forbidden"}   # bloqueado, HTTP 403
```

**Teste de rate limit:** inundei o endpoint com mais de 2.000 requisições em menos de 5 minutos a partir de uma única origem — a regra de rate limit do WAF disparou, a origem foi bloqueada, o alarme do CloudWatch foi acionado e o alerta via SNS chegou à caixa de entrada de segurança em segundos.

**Bloqueio dinâmico de IP:** simulei requisições de um IP sinalizado — a Lambda detectou o padrão, atualizou o IP Set do WAF programaticamente e confirmou que a mesma origem foi bloqueada na requisição seguinte, sem qualquer intervenção manual.

Os três cenários estão registrados de ponta a ponta no CloudWatch, então todo bloqueio, todo alerta e toda mudança de regra é rastreável — que é o ponto real: não apenas parar a requisição, mas provar que aconteceu e conseguir mostrar essa prova numa auditoria.

## Resultados

- Tráfego malicioso (payloads de SQLi, abuso de rate limit, IPs sinalizados) bloqueado automaticamente, sem intervenção manual após o deploy.
- Rastreabilidade completa de requisição a resposta via CloudWatch — suporta requisitos de auditoria LGPD/PCI DSS em vez de apenas alegar compliance.
- Tempo médio até o alerta: segundos (o SNS dispara diretamente pelo alarme do CloudWatch e pelo próprio caminho de detecção da Lambda).
- Todo o stack construído e testado no Free Tier da AWS — custo zero de infraestrutura durante o desenvolvimento.

## Stack

`AWS API Gateway` · `AWS Lambda (Python)` · `AWS WAF` · `Amazon CloudWatch (Logs, Métricas, Alarmes, Logs Insights)` · `Amazon SNS` · `IAM`

## Roadmap

- Expandir as regras customizadas do WAF para cobrir padrões de brute force e enumeração de endpoints.
- Alimentar eventos do CloudWatch/SNS em um SIEM/SOAR corporativo para correlação centralizada.
- Restringir o acesso direto ao API Gateway apenas a tráfego originado do CloudFront (header secreto / autenticação mútua).
- Construir dashboards no CloudWatch para KPIs de segurança e performance em tempo real.
- Estender a arquitetura para multi-cloud (Azure, GCP) para resiliência entre provedores e bloqueio sincronizado de IPs.

---

*Originalmente desenvolvido como projeto aplicado de conclusão da pós-graduação em Cloud Computing e IA (XP Educação, 2025). Este repositório apresenta a implementação técnica; o enquadramento acadêmico (Canvas, personas, modelo de negócio) foi removido para fins de portfólio.*
