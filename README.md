# GHIRUST

Ferramenta de engenharia reversa de binários, escrita em Rust, com interface
de linha de comando e aplicativo desktop. O projeto carrega metadados de
executáveis, analisa código x86/x86-64 e permite explorar funções, referências,
strings e pseudocódigo reconstruído.

> **Escopo:** GHIRUST é uma implementação independente. A reconstrução de
> pseudocódigo é heurística e não há alegação de equivalência semântica ou
> compatibilidade completa com Ghidra.

## Recursos

- Carregamento de metadados PE, ELF, Mach-O e WebAssembly.
- Decodificação x86 e x86-64, recuperação de funções, blocos, CFGs e
  referências cruzadas.
- IR própria (GUIR) e reconstrução heurística de pseudocódigo C-like.
- Projetos persistentes com análises, sessões e anotações do usuário.
- Extração de strings, indexação, pesquisa e exportação com uso de memória
  limitado.
- Aplicativo desktop para navegar pela listagem, pseudocódigo, símbolos,
  referências, strings, tarefas e grafo de fluxo.
- Limites de recursos, reservas de memória e telemetria de CPU/RAM. GPU/VRAM
  são indicadas como indisponíveis, pois não há backend de GPU.

## Requisitos

- Rust 1.85 ou superior (edição 2024).
- Windows com toolchain MSVC e Windows SDK para a compilação nativa no Windows.
- Para reconstruir os fixtures C++: compilador MSVC disponível no `PATH`.
- Para executar a comparação opcional com Ghidra: JDK e uma instalação local
  do Ghidra 12.2.

## Compilar e executar

Os comandos abaixo partem da raiz do repositório e usam PowerShell.

```powershell
cd ghirust

# Verificar compilação e executar os testes
cargo test --workspace

# Verificar formatação e lint
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# Diagnosticar o ambiente
cargo run --release -p ghirust-cli -- doctor

# Abrir a interface desktop
cargo run --release -p ghirust-gui
```

### Exemplos da CLI

Os exemplos de análise usam o fixture `demo.dll` incluído em
`tests/objectives/binaries/`.

```powershell
# Analisar e salvar o resultado
cargo run --release -p ghirust-cli -- analyze ..\tests\objectives\binaries\demo.dll `
  --save ..\tests\objectives\reports\demo.analysis.json

# Inspecionar funções, instruções e pseudocódigo
cargo run --release -p ghirust-cli -- functions ..\tests\objectives\binaries\demo.dll
cargo run --release -p ghirust-cli -- disasm ..\tests\objectives\binaries\demo.dll `
  --function demo_add
cargo run --release -p ghirust-cli -- decompile ..\tests\objectives\binaries\demo.dll `
  --function demo_fact

# Criar um projeto e importar um binário
cargo run -p ghirust-cli -- project create ..\demo-project --name "Demo"
cargo run -p ghirust-cli -- project import ..\demo-project `
  ..\tests\objectives\binaries\demo.dll
```

Use `cargo run -p ghirust-cli -- --help` ou acrescente `--help` a um comando
para consultar todas as opções disponíveis.

## Testes e comparação

Os testes automatizados da workspace são executados com `cargo test
--workspace`. Os fixtures e scripts de validação estão em
`tests/objectives/`. Para reconstruir os binários de teste e verificar seu
comportamento no Windows:

```powershell
powershell -ExecutionPolicy Bypass -File tests\objectives\build_fixtures.ps1
powershell -ExecutionPolicy Bypass -File tests\objectives\run_behavior.ps1
```

A comparação opcional com Ghidra requer JDK, Ghidra 12.2 e a configuração de
`GHIDRA_HOME` descrita em `tests/objectives/ghidra/README.md`. As evidências
disponíveis e as limitações conhecidas estão documentadas na
[matriz de compatibilidade](docs/ghira_compatibility_matrix.md) e nos
[resultados de benchmarks](docs/benchmarks/results.md).

## Estrutura do repositório

```text
ghirust/
  crates/
    ghirust-core/   motor de análise e funcionalidades compartilhadas
    ghirust-cli/    interface de linha de comando
    ghirust-gui/    aplicativo desktop
  docs/             documentação técnica da workspace
tests/
  objectives/       fontes, fixtures e ferramentas de validação
docs/               arquitetura, testes e benchmarks
```

Consulte também [o status do desenvolvimento](DEVELOPMENT_STATUS.md) e a
[documentação de arquitetura](docs/architecture/overview.md).

## Limitações conhecidas

- A decodificação de instruções está limitada a x86/x86-64.
- O pseudocódigo é heurístico; várias instruções são sinalizadas como não
  suportadas em vez de receberem uma interpretação especulativa.
- Não há recuperação completa de tipos, estruturas, ponteiros ou SSA.
- Resultados comparativos cobrem fixtures pequenos; não demonstram equivalência
  semântica com Ghidra nem desempenho em binários grandes.
- A interface e a localização ainda estão em desenvolvimento.
- Não existe backend de GPU.

Mais detalhes e evidências estão na
[matriz de compatibilidade](docs/ghira_compatibility_matrix.md).

## Licença e proveniência

Consulte [LICENSE](LICENSE) para os termos do repositório; os crates também
declaram seu identificador de licença nos respectivos `Cargo.toml`.
O código-fonte de referência do Ghidra, se presente localmente em
`ghira_original_source_code/`, é mantido fora deste repositório pelo
`.gitignore` e continua sujeito à licença própria. As dependências mantêm suas
respectivas licenças.
