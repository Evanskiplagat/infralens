import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { App } from "./App";

describe("App", () => {
  it("renders the InfraLens landing content", () => {
    render(<App />);

    expect(
      screen.getByRole("heading", { name: "InfraLens" })
    ).toBeInTheDocument();
    expect(screen.getByText(/Deprecated/i)).toBeInTheDocument();
    expect(screen.getByText(/InfraLens is now a CLI/i)).toBeInTheDocument();
  });
});
