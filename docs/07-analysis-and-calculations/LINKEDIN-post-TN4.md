# LinkedIn Post - INF1430 Symmetric Encryption Project

I just completed the final phase of my INF1430 final project, which also marks the completion of my Computer Science major at Universite TELUQ. My major specialized me in software development and cybersecurity, which is why I chose a cross-platform comparison of symmetric encryption algorithms (AES, DES, 3DES, Twofish, and ChaCha20) on x86 and ARM.

One thing I am especially proud of is that this was not a one-shot benchmark. The project was executed with a full Software Development Life Cycle (SDLC) mindset inspired by Ian Sommerville, from analysis and planning to final consolidation and reporting.

Key highlights:

- SDLC-driven execution from planning to consolidated final analysis.
- DevSecOps-oriented workflow with testing, coverage, dependency audits, and integrity checks.
- Cross-platform benchmarking on x86 and ARM under a unified protocol.
- Quantum and AI impact research to support long-term crypto-agility.

SDLC steps followed:

- Phase 1: analyzed cryptographic foundations and planned the experimental protocol.
- Phase 2: designed a modular architecture and prepared the codebase and execution environment.
- Phase 3: ran an initial validation and measurement campaign (functional checks plus first performance/stability signals).
- Phase 4: consolidated the dataset, re-ran the full benchmark suite, regenerated final charts/tables, and completed the final analysis report.

Software engineering highlights:

- Object-oriented, modular, layered architecture.
- Clear separation of responsibilities between primitives, modes, and orchestration.
- Reuse-first extensibility, new algorithms and modes can be added with minimal rewrites.
- Core artifacts: conceptual architecture, UML package/class/sequence/deployment diagrams, formal KAT-based validation strategy, and implementation-readiness evidence for cross-platform experimentation.

Another major goal was trustworthiness of results. Before focusing on performance, I validated implementations against formal references and known-answer vectors (KAT), including NIST standards and RFC sources. I then reinforced reliability with a DevSecOps approach: automated tests, coverage tracking, dependency and static-security audits, and integrity checks for external vectors.

How DevSecOps was applied in practice:

- Functional correctness gates with KAT against formal references (NIST/RFC + official vectors).
- Automated regression testing with pytest.
- Coverage tracking to monitor verification depth over time.
- Dependency vulnerability scanning with pip-audit.
- Static security analysis with CodeQL and Bandit.
- Automated dependency update and alert workflow with Dependabot.
- Integrity verification of external vector files using SHA-256 checks.

Forward-looking research included:

- Quantum impact assessment on cryptographic risk and long-term algorithm selection.
- AI impact analysis for security governance, including reliability and risk-management perspectives.
- A practical focus on crypto-agility, keeping symmetric crypto decisions aligned with evolving standards.

Outcome:

- Functional correctness first.
- Performance measured with statistical confidence.
- Reproducibility across platforms.
- Security-oriented quality gates throughout the pipeline.

This project started as a symmetric cryptography comparison, but I intentionally gave it a modern extension. Nowadays, AI can accelerate coding dramatically, so critical thinking matters even more. I used that speed advantage to go further, strengthen the project with DevSecOps practices, harden the code properly, and expand the research into quantum and AI impact. Faster execution gave me more time to learn deeper and raise the quality of the work.

#Cybersecurity #Cryptography #SoftwareEngineering #SDLC #Python #Benchmarking #NIST #DevSecOps #Reproducibility #AI #PostQuantumCrypto
