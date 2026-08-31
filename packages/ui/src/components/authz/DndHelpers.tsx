// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import {
  DndContext,
  DragOverlay,
  KeyboardSensor,
  PointerSensor,
  closestCenter,
  useDraggable,
  useDroppable,
  useSensor,
  useSensors,
  type Active,
  type DragEndEvent,
  type DragStartEvent,
} from "@dnd-kit/core";
import {
  SortableContext,
  arrayMove,
  sortableKeyboardCoordinates,
  useSortable,
  verticalListSortingStrategy,
} from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import type { ReactNode } from "react";
import { useState } from "react";

function dragOverlayLabel(active: Active): string {
  const label = active.data.current?.label;
  if (typeof label === "string" && label.length > 0) {
    return label;
  }
  return String(active.id);
}

export function AuthzDndProvider({
  children,
  onDragEnd,
}: {
  children: ReactNode;
  onDragEnd: (event: DragEndEvent) => void;
}) {
  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 6 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  );
  const [activeLabel, setActiveLabel] = useState<string | null>(null);

  function onDragStart(event: DragStartEvent) {
    setActiveLabel(dragOverlayLabel(event.active));
  }

  function handleDragEnd(event: DragEndEvent) {
    setActiveLabel(null);
    onDragEnd(event);
  }

  return (
    <DndContext
      sensors={sensors}
      collisionDetection={closestCenter}
      onDragStart={onDragStart}
      onDragEnd={handleDragEnd}
    >
      {children}
      <DragOverlay>
        {activeLabel ? <span className="dnd-drag-overlay tag-chip">{activeLabel}</span> : null}
      </DragOverlay>
    </DndContext>
  );
}

export function DraggableChip({
  id,
  label,
  disabled = false,
}: {
  id: string;
  label: string;
  disabled?: boolean;
}) {
  const { attributes, listeners, setNodeRef, transform, isDragging } = useDraggable({
    id,
    data: { label },
    disabled,
  });
  const style = transform
    ? { transform: `translate(${transform.x}px, ${transform.y}px)` }
    : undefined;

  return (
    <button
      type="button"
      ref={setNodeRef}
      style={style}
      className={isDragging ? "tag-chip dnd-dragging" : "tag-chip"}
      {...listeners}
      {...attributes}
      disabled={disabled}
    >
      {label}
    </button>
  );
}

export function DropZone({
  id,
  label,
  children,
  emptyHint,
}: {
  id: string;
  label: string;
  children: ReactNode;
  emptyHint?: string;
}) {
  const { isOver, setNodeRef } = useDroppable({ id });

  return (
    <div
      ref={setNodeRef}
      className={isOver ? "authz-drop-zone authz-drop-zone--active" : "authz-drop-zone"}
    >
      <p className="permissions-hint">{label}</p>
      {children}
      {emptyHint && !children ? <p className="muted">{emptyHint}</p> : null}
    </div>
  );
}

export function SortableListItem({
  id,
  label,
  children,
}: {
  id: string;
  label?: string;
  children: ReactNode;
}) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({
    id,
    data: label ? { label } : undefined,
  });
  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.5 : 1,
  };

  return (
    <li ref={setNodeRef} style={style} className="authz-sortable-item">
      <button type="button" className="authz-drag-handle" {...attributes} {...listeners} aria-label="Reorder">
        ⋮⋮
      </button>
      {children}
    </li>
  );
}

export { SortableContext, arrayMove, verticalListSortingStrategy };
