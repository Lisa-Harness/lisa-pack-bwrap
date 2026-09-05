"""Read-only layer listing operation for the bwrap pack."""

from __future__ import annotations

from pathlib import Path

from kernel.models import OperationExecutionContext, OperationResult

from lisa_packs.bwrap.layers import list_layers

OPERATION_ID = "layers_list"


async def execute(ctx: OperationExecutionContext) -> OperationResult:
    """List overlayfs layers under the layers dir for user visibility."""
    base = Path(ctx.data_dir) if getattr(ctx, "data_dir", "") else Path.home() / ".lisa"
    layers_dir = base / "layers"
    layers = list_layers(layers_dir)
    payload = [
        {"layer_id": layer.layer_id, "path": layer.path, "size_bytes": layer.size_bytes}
        for layer in layers
    ]
    return OperationResult(
        status="success",
        output_text=f"{len(payload)} layer(s) under {layers_dir}",
        output_json={"layers_dir": str(layers_dir), "layers": payload},
    )
